#include "analysis.h"

#include "diagnostic.h"

#include "llvm/ADT/STLFunctionalExtras.h"
#include "llvm/DebugInfo/DWARF/DWARFContext.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/Endian.h"
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

    bool StableMetadata::contains(uint32_t rva, uint32_t size) const {
        const RvaRange range{rva, uint64_t(rva) + size};
        const auto mapped = image.mapRva(rva, size);
        return mapped && mapped->section.immutable() && !relocations.firstOverlap(range) &&
               rangesIn(writes, range).empty();
    }

    bool StableMetadata::containsUnwindRecord(const FunctionRange &function) const {
        const auto &directory = image.module().exceptions;
        if (!directory || function.indices.empty() ||
            !contains(function.record.unwind, function.unwindInfoSize)) {
            return false;
        }

        const uint32_t table = directory->rva;
        return llvm::all_of(function.indices, [&](size_t index) {
            constexpr uint32_t recordSize = sizeof(llvm::Win64EH::RuntimeFunction);
            const auto rva = uint64_t(table) + index * recordSize;
            return rva <= UINT32_MAX && contains(static_cast<uint32_t>(rva), recordSize);
        });
    }

    namespace {
        auto key(const RuntimeFunction &r) { return std::tie(r.begin, r.end, r.unwind); }

        void inspectUnwindRecord(const ParsedImage &image, FunctionRange &function,
                                 function_ref<void(StringRef)> invalid) {
            const auto unwind = function.record.unwind;
            constexpr size_t headerSize = offsetof(Win64EH::UnwindInfo, UnwindCodes);
            const auto data = image.mapRva(unwind);

            if (!unwind || unwind % 4 || !data || data->bytes.size() < headerSize) {
                invalid("unwind RVA must point to a file-backed, aligned AMD64 unwind header");
                return;
            }

            Win64EH::UnwindInfo header{};
            std::memcpy(&header, data->bytes.data(), headerSize);

            if (header.getVersion() != 1 && header.getVersion() != 2) {
                function.unsupportedUnwindVersion = header.getVersion();
                return;
            }

            function.chainedFragment = header.getFlags() & Win64EH::UNW_ChainInfo;
            function.hasUnwindHandler =
                header.getFlags() & (Win64EH::UNW_ExceptionHandler | Win64EH::UNW_TerminateHandler);
            const size_t codesEnd = headerSize + header.NumCodes * sizeof(Win64EH::UnwindCode);

            if (data->bytes.size() < codesEnd) {
                invalid("truncated unwind code array");
                return;
            }

            const size_t trailer = alignTo(codesEnd, 4);
            size_t extent = codesEnd;

            if (function.chainedFragment) {
                if (function.hasUnwindHandler) {
                    invalid("chained unwind info also declares a handler");
                }

                extent = trailer + sizeof(Win64EH::RuntimeFunction);

                if (data->bytes.size() < extent) {
                    invalid("truncated chained runtime function");
                    return;
                }
            } else if (function.hasUnwindHandler) {
                extent = trailer + sizeof(uint32_t);

                if (data->bytes.size() < extent) {
                    invalid("truncated unwind handler RVA");
                    return;
                }

                function.handlerRva = support::endian::read32le(data->bytes.data() + trailer);
                const auto languageData = uint64_t(unwind) + extent;

                if (header.getVersion() == 1 &&
                    header.getFlags() == Win64EH::UNW_ExceptionHandler &&
                    languageData <= UINT32_MAX) {
                    function.exceptionDataRva = static_cast<uint32_t>(languageData);
                }
            }

            function.unwindInfoSize = static_cast<uint32_t>(extent);
        }
    } // namespace

    std::optional<int64_t> amd64ImportThunkSlot(uint32_t rva, StringRef bytes) {
        if (bytes.size() != amd64ImportThunkSize || !bytes.starts_with("\xff\x25")) {
            return {};
        }

        const auto displacement = SignExtend64<32>(support::endian::read32le(bytes.data() + 2));
        return int64_t(rva) + amd64ImportThunkSize + displacement;
    }

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

            if (unsigned tail = table.trailingBytes()) {
                diagnostics.push_back({"PARTIAL_RUNTIME_FUNCTION",
                                       std::to_string(tail) +
                                           " trailing exception directory bytes at RVA " +
                                           hex(uint64_t(table.rva) + table.size - tail),
                                       {records.size()}});
            }
        }

        for (auto &f : ranges) {
            const auto begin = f.record.begin, end = f.record.end;
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

            inspectUnwindRecord(*source, f, invalid);
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
