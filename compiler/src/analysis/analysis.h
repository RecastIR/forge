#pragma once

#include "analysis/exception_scope.h"
#include "pe/image.h"

namespace forge {
    enum class RecordDefect { InvalidRecord, UnmappedCode };

    inline constexpr uint32_t amd64ImportThunkSize = 6;
    std::optional<int64_t> amd64ImportThunkSlot(uint32_t rva, llvm::StringRef bytes);

    struct FunctionRange {
        RuntimeFunction record;
        std::vector<size_t> indices;
        bool entry = false, callback = false;
        std::optional<RecordDefect> defect;
        bool chainedFragment = false;
        bool hasUnwindHandler = false;
        // File-backed header, codes and any mandatory aligned trailer.
        uint32_t unwindInfoSize = 0;
        std::optional<uint32_t> handlerRva;
        std::optional<uint32_t> exceptionDataRva;
        std::optional<unsigned> unsupportedUnwindVersion;
        std::optional<size_t> overlapGroup;
        std::string name, file;
        unsigned line = 0;

        bool covered() const { return !defect && !overlapGroup && !unsupportedUnwindVersion; }

        bool eligible() const { return covered() && !chainedFragment; }
    };

    // All three views belong to the same parsed image.
    struct StableMetadata {
        const ParsedImage &image;
        const RelocationIndex &relocations;
        llvm::ArrayRef<RvaRange> writes;

        bool contains(uint32_t rva, uint32_t size) const;
        bool containsUnwindRecord(const FunctionRange &function) const;
    };

    struct Finding {
        std::string code, message;
        std::vector<size_t> records;
    };

    enum class DebugInfo { Omit, Enrich };

    class AnalyzedImage {
      public:
        AnalyzedImage(std::unique_ptr<ParsedImage> image, DebugInfo debugInfo);
        AnalyzedImage(const AnalyzedImage &) = delete;
        AnalyzedImage &operator=(const AnalyzedImage &) = delete;

        const ParsedImage &image() const { return *source; }

        const Module &module() const { return source->module(); }

        const std::vector<FunctionRange> &functions() const { return ranges; }

        const std::vector<Finding> &findings() const { return diagnostics; }

        // Executable inspection calls this only for a handler of interest. Ordinary
        // function discovery remains independent of import table details.
        std::optional<CSpecificHandler> cSpecificHandler(const FunctionRange &function) const;

        const std::vector<std::pair<uint32_t, uint32_t>> &unknownRanges() const { return unknown; }

      private:
        std::unique_ptr<ParsedImage> source;
        std::vector<FunctionRange> ranges;
        std::vector<std::pair<uint32_t, uint32_t>> unknown;
        std::vector<Finding> diagnostics;

        void discoverAmd64Functions();
        void markOverlaps();
        void findUnknown();
        void enrichFunctions();
    };
} // namespace forge
