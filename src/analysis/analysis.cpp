#include "analysis.h"

#include "diagnostic.h"

#include "llvm/DebugInfo/DWARF/DWARFContext.h"
#include "llvm/Object/ObjectFile.h"
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
    } // namespace

    // A connected component reports each record once even for deeply nested intervals.
    void AnalyzedImage::markOverlaps() {
        std::vector<size_t> group;
        uint32_t end = 0;
        auto finish = [&] {
            if (group.size() > 1) {
                Finding finding{"FUNCTION_RANGE_OVERLAP", "overlapping exception ranges", {}};

                for (auto i : group) {
                    auto &f = ranges[i];
                    f.overlapGroup = diagnostics.size();
                    finding.records.insert(finding.records.end(), f.indices.begin(),
                                           f.indices.end());
                }

                diagnostics.push_back(std::move(finding));
            }

            group.clear();
        };

        for (size_t i = 0; i < ranges.size(); ++i) {
            const auto &r = ranges[i].record;

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

    void AnalyzedImage::findUnknown() {
        for (const auto &s : module().sections) {
            if (s.permissions[2] != 'x') {
                continue;
            }

            uint32_t cursor = s.rva, end = s.rva + s.virtualSize;
            auto it = std::lower_bound(
                ranges.begin(), ranges.end(), cursor,
                [](const auto &f, uint32_t addr) { return f.record.begin < addr; });

            for (; it != ranges.end() && it->record.begin < end; ++it) {
                if (!it->covered()) {
                    continue;
                }

                if (cursor < it->record.begin) {
                    unknown.emplace_back(cursor, it->record.begin);
                }

                cursor = it->record.end;
            }

            if (cursor < end) {
                unknown.emplace_back(cursor, end);
            }
        }

        llvm::sort(unknown);
    }

    AnalyzedImage::AnalyzedImage(std::unique_ptr<ParsedImage> image, DebugInfo debugInfo)
        : source(std::move(image)) {
        if (!source) {
            throw InspectionError("function analysis requires a parsed image",
                                  FailureCode::AnalysisInternal);
        }

        discoverAmd64Functions();

        if (debugInfo == DebugInfo::Enrich) {
            enrichFunctions();
        }
    }

    void AnalyzedImage::discoverAmd64Functions() {
        std::vector<uint32_t> callbacks;

        if (module().tls) {
            for (auto va : module().tls->callbackVas) {
                if (va >= module().imageBase && va - module().imageBase <= UINT32_MAX) {
                    callbacks.push_back(static_cast<uint32_t>(va - module().imageBase));
                }
            }
        }

        llvm::sort(callbacks);

        if (module().exceptions) {
            const auto &table = *module().exceptions;
            const auto &records = table.functions;
            std::vector<size_t> indices(records.size());
            std::iota(indices.begin(), indices.end(), 0);
            std::stable_sort(indices.begin(), indices.end(),
                             [&](auto x, auto y) { return key(records[x]) < key(records[y]); });

            for (auto i : indices) {
                const auto &r = records[i];

                if (ranges.empty() || key(ranges.back().record) != key(r)) {
                    FunctionRange f{};
                    f.record = r;
                    ranges.push_back(std::move(f));
                }

                ranges.back().indices.push_back(i);
            }

            if (unsigned tail = table.size % 12) {
                diagnostics.push_back({"PARTIAL_RUNTIME_FUNCTION",
                                       std::to_string(tail) +
                                           " trailing exception directory bytes at RVA " +
                                           hex(uint64_t(table.rva) + table.size - tail),
                                       {records.size()}});
            }
        }

        for (auto &f : ranges) {
            auto [begin, end, unwind] = f.record;
            auto invalid = [&](StringRef reason,
                               RecordDefect defect = RecordDefect::InvalidRecord) {
                // Report every finding, retaining the first defect for entry selection.
                if (!f.defect) {
                    f.defect = defect;
                }

                diagnostics.push_back(
                    {"INVALID_FUNCTION_RECORD", hex(begin) + ": " + reason.str(), f.indices});
            };

            if (end <= begin) {
                invalid("empty or reversed range");
            } else {
                auto code = source->mapRva(begin, end - begin);

                if (!code || code->section.permissions[2] != 'x') {
                    invalid("range outside a single file-backed executable section",
                            code ? RecordDefect::InvalidRecord : RecordDefect::UnmappedCode);
                }

                f.entry = module().entryPoint && begin <= module().entryPoint &&
                          module().entryPoint < end;
                auto cb = llvm::lower_bound(callbacks, begin);
                f.callback = cb != callbacks.end() && *cb < end;
            }

            constexpr size_t headerSize = offsetof(Win64EH::UnwindInfo, UnwindCodes);
            auto data = source->mapRva(unwind);

            if (!unwind || unwind % 4 || !data || data->bytes.size() < headerSize) {
                invalid("unwind RVA must point to a file-backed, aligned AMD64 unwind header");
                continue;
            }

            Win64EH::UnwindInfo header{};
            std::memcpy(&header, data->bytes.data(), headerSize);

            if (header.getVersion() != 1 && header.getVersion() != 2) {
                f.unsupportedUnwindVersion = header.getVersion();
                continue;
            }

            f.chainedFragment = header.getFlags() & Win64EH::UNW_ChainInfo;
            const size_t codesEnd = headerSize + header.NumCodes * sizeof(Win64EH::UnwindCode);

            if (data->bytes.size() < codesEnd) {
                invalid("truncated unwind code array");
            } else if (f.chainedFragment) {
                if (header.getFlags() &
                    (Win64EH::UNW_ExceptionHandler | Win64EH::UNW_TerminateHandler)) {
                    invalid("chained unwind info also declares a handler");
                }

                const size_t trailer = alignTo(codesEnd, 4);

                if (data->bytes.size() < trailer + sizeof(Win64EH::RuntimeFunction)) {
                    invalid("truncated chained runtime function");
                }
            }
        }

        markOverlaps();
        findUnknown();
    }

    void AnalyzedImage::enrichFunctions() {
        if (!llvm::any_of(module().sections,
                          [](const Section &s) { return s.name == ".debug_info"; })) {
            return;
        }

        auto context =
            DWARFContext::create(source->object(), DWARFContext::ProcessDebugRelocations::Ignore,
                                 nullptr, "", consumeError, consumeError);
        DILineInfoSpecifier spec(DILineInfoSpecifier::FileLineInfoKind::RawValue,
                                 DINameKind::LinkageName);

        for (auto &f : ranges) {
            if (!f.eligible() || module().imageBase > UINT64_MAX - f.record.begin) {
                continue;
            }

            auto frames = context->getInliningInfoForAddress(
                {module().imageBase + f.record.begin, object::SectionedAddress::UndefSection},
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
} // namespace forge
