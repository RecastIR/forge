#include "analysis.h"

#include "llvm/DebugInfo/DWARF/DWARFContext.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/Win64EH.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <numeric>
#include <tuple>

namespace forge {
    using namespace llvm;

    namespace {
        auto key(const RuntimeFunction &r) { return std::tie(r.begin, r.end, r.unwind); }

        // A connected component reports each record once even for deeply nested intervals.
        void markOverlaps(Analysis &a) {
            std::vector<size_t> group;
            uint32_t end = 0;
            auto finish = [&] {
                if (group.size() > 1) {
                    Finding finding{"FUNCTION_RANGE_OVERLAP", "overlapping exception ranges", {}};
                    for (auto i : group) {
                        auto &f = a.functions[i];
                        f.overlapGroup = a.findings.size();
                        finding.records.insert(finding.records.end(), f.indices.begin(),
                                               f.indices.end());
                    }
                    a.findings.push_back(std::move(finding));
                }
                group.clear();
            };
            for (size_t i = 0; i < a.functions.size(); ++i) {
                const auto &r = a.functions[i].record;
                if (r.begin >= r.end) {
                    continue;
                }
                if (r.begin >= end) {
                    finish();
                }
                group.push_back(i);
                end = std::max(end, r.end);
            }
            finish();
        }

        void findUnknown(Analysis &a) {
            for (const auto &s : a.module.sections) {
                if (s.permissions[2] != 'x') {
                    continue;
                }
                uint32_t cursor = s.rva, end = s.rva + s.virtualSize;
                auto it = std::lower_bound(
                    a.functions.begin(), a.functions.end(), cursor,
                    [](const auto &f, uint32_t addr) { return f.record.begin < addr; });
                for (; it != a.functions.end() && it->record.begin < end; ++it) {
                    if (!it->covered()) {
                        continue;
                    }
                    if (cursor < it->record.begin) {
                        a.unknown.emplace_back(cursor, it->record.begin);
                    }
                    cursor = it->record.end;
                }
                if (cursor < end) {
                    a.unknown.emplace_back(cursor, end);
                }
            }
            llvm::sort(a.unknown);
        }

        StringRef status(const FunctionRange &f) {
            if (f.invalid) {
                return "invalid";
            }
            if (f.overlapGroup) {
                return "conflicting";
            }
            if (f.unsupportedUnwindVersion) {
                return "unsupported";
            }
            return "valid";
        }
    } // namespace

    Analysis discover(Module module, StringRef file) {
        Analysis a{std::move(module), {}, {}, {}};
        std::vector<uint32_t> callbacks;
        if (a.module.tls) {
            for (auto va : a.module.tls->callbackVas) {
                if (va >= a.module.imageBase && va - a.module.imageBase <= UINT32_MAX) {
                    callbacks.push_back(static_cast<uint32_t>(va - a.module.imageBase));
                }
            }
        }
        llvm::sort(callbacks);

        if (a.module.exceptions) {
            const auto &table = *a.module.exceptions;
            const auto &records = table.functions;
            std::vector<size_t> indices(records.size());
            std::iota(indices.begin(), indices.end(), 0);
            std::stable_sort(indices.begin(), indices.end(),
                             [&](auto x, auto y) { return key(records[x]) < key(records[y]); });
            for (auto i : indices) {
                const auto &r = records[i];
                if (a.functions.empty() || key(a.functions.back().record) != key(r)) {
                    FunctionRange f{};
                    f.record = r;
                    a.functions.push_back(std::move(f));
                }
                a.functions.back().indices.push_back(i);
            }
            if (unsigned tail = table.size % 12) {
                a.findings.push_back({"PARTIAL_RUNTIME_FUNCTION",
                                      std::to_string(tail) +
                                          " trailing exception directory bytes at RVA " +
                                          hex(uint64_t(table.rva) + table.size - tail),
                                      {records.size()}});
            }
        }
        for (auto &f : a.functions) {
            auto [begin, end, unwind] = f.record;
            auto invalid = [&](StringRef reason) {
                f.invalid = true;
                a.findings.push_back(
                    {"INVALID_FUNCTION_RECORD", hex(begin) + ": " + reason.str(), f.indices});
            };
            if (end <= begin) {
                invalid("empty or reversed range");
            } else {
                auto code = mapRva(a.module.sections, file, begin, end - begin);
                if (!code || code->section.permissions[2] != 'x') {
                    invalid("range outside a single file-backed executable section");
                }
                f.entry = a.module.entryPoint && begin <= a.module.entryPoint &&
                          a.module.entryPoint < end;
                auto cb = llvm::lower_bound(callbacks, begin);
                f.callback = cb != callbacks.end() && *cb < end;
            }
            constexpr size_t HeaderSize = offsetof(Win64EH::UnwindInfo, UnwindCodes);
            auto data = mapRva(a.module.sections, file, unwind);
            if (!unwind || unwind % 4 || !data || data->bytes.size() < HeaderSize) {
                invalid("unwind RVA must point to a file-backed, aligned AMD64 unwind header");
                continue;
            }
            Win64EH::UnwindInfo header{};
            std::memcpy(&header, data->bytes.data(), HeaderSize);
            if (header.getVersion() != 1 && header.getVersion() != 2) {
                f.unsupportedUnwindVersion = header.getVersion();
                continue;
            }
            f.chainedFragment = header.getFlags() & Win64EH::UNW_ChainInfo;
            const size_t CodesEnd = HeaderSize + header.NumCodes * sizeof(Win64EH::UnwindCode);
            if (data->bytes.size() < CodesEnd) {
                invalid("truncated unwind code array");
            } else if (f.chainedFragment) {
                if (header.getFlags() &
                    (Win64EH::UNW_ExceptionHandler | Win64EH::UNW_TerminateHandler)) {
                    invalid("chained unwind info also declares a handler");
                }
                const size_t Trailer = alignTo(CodesEnd, 4);
                if (data->bytes.size() < Trailer + sizeof(Win64EH::RuntimeFunction)) {
                    invalid("truncated chained runtime function");
                }
            }
        }
        markOverlaps(a);
        findUnknown(a);
        return a;
    }

    void enrichFunctions(Analysis &a, const object::ObjectFile &obj) {
        if (!llvm::any_of(a.module.sections,
                          [](const Section &s) { return s.name == ".debug_info"; })) {
            return;
        }
        auto context = DWARFContext::create(obj, DWARFContext::ProcessDebugRelocations::Ignore,
                                            nullptr, "", consumeError, consumeError);
        DILineInfoSpecifier spec(DILineInfoSpecifier::FileLineInfoKind::RawValue,
                                 DINameKind::LinkageName);
        for (auto &f : a.functions) {
            if (!f.eligible() || a.module.imageBase > UINT64_MAX - f.record.begin) {
                continue;
            }
            auto frames = context->getInliningInfoForAddress(
                {a.module.imageBase + f.record.begin, object::SectionedAddress::UndefSection},
                spec);
            if (!frames.getNumberOfFrames()) {
                continue;
            }
            const auto &info = frames.getFrame(frames.getNumberOfFrames() - 1);
            if (info.FunctionName != DILineInfo::BadString &&
                info.FunctionName != DILineInfo::Addr2LineBadString) {
                f.name = json::fixUTF8(info.FunctionName);
            }
            if (info.Line && info.FileName != DILineInfo::BadString &&
                info.FileName != DILineInfo::Addr2LineBadString) {
                f.file = json::fixUTF8(info.FileName);
                f.line = info.Line;
            }
        }
    }

    void printAnalysis(const Analysis &a, bool jsonFormat, raw_ostream &out) {
        if (!jsonFormat) {
            out << "Functions (" << a.functions.size() << "), source: PE exception directory\n";

            for (const auto &f : a.functions) {
                const auto &r = f.record;

                out << "  " << hex(r.begin) << ".." << hex(r.end);

                if (r.end >= r.begin) {
                    out << " (" << r.end - r.begin << " bytes)";
                }

                out << " unwind " << hex(r.unwind) << " " << status(f) << " records";

                for (auto index : f.indices) {
                    out << " " << index;
                }

                if (f.entry) {
                    out << " entry";
                }

                if (f.callback) {
                    out << " TLS callback";
                }

                if (f.chainedFragment) {
                    out << " chained fragment";
                }

                if (f.unsupportedUnwindVersion) {
                    out << " unwind version " << *f.unsupportedUnwindVersion;
                }

                if (!f.name.empty()) {
                    out << " " << f.name;
                }

                if (f.line) {
                    out << " " << f.file << ":" << f.line;
                }

                out << "\n";
            }

            for (auto [begin, end] : a.unknown) {
                out << "  Unknown executable range " << hex(begin) << ".." << hex(end) << "\n";
            }

            return;
        }

        json::Array functions, unknown, diagnostics;

        for (const auto &f : a.functions) {
            const auto &r = f.record;

            json::Object o{{"start_rva", hex(r.begin)},
                           {"end_rva", hex(r.end)},
                           {"unwind_rva", hex(r.unwind)},
                           {"source", "exception_directory"},
                           {"record_indices", json::Array(f.indices)},
                           {"status", status(f)},
                           {"liftable", f.eligible()},
                           {"contains_entry_point", f.entry},
                           {"contains_tls_callback", f.callback},
                           {"size", nullptr}};

            if (r.end >= r.begin) {
                o["size"] = r.end - r.begin;
            }

            if (f.overlapGroup) {
                o["overlap_diagnostic"] = *f.overlapGroup;
            }

            if (f.chainedFragment) {
                o["chained_fragment"] = true;
            }

            if (f.unsupportedUnwindVersion) {
                o["unwind_version"] = *f.unsupportedUnwindVersion;
            }

            if (!f.name.empty()) {
                o["name"] = f.name;
            }

            if (f.line) {
                o["location"] = json::Object{{"file", f.file}, {"line", f.line}};
            }

            functions.push_back(std::move(o));
        }

        for (auto [begin, end] : a.unknown) {
            unknown.push_back(json::Object{{"start_rva", hex(begin)}, {"end_rva", hex(end)}});
        }

        for (const auto &d : a.findings) {
            diagnostics.push_back(json::Object{{"code", d.code},
                                               {"severity", "warning"},
                                               {"message", d.message},
                                               {"record_indices", json::Array(d.records)}});
        }

        out << formatv("{0:2}\n",
                       json::Value(json::Object{{"schema_version", 1},
                                                {"functions", std::move(functions)},
                                                {"unknown_executable_ranges", std::move(unknown)},
                                                {"diagnostics", std::move(diagnostics)}}));
    }
} // namespace forge
