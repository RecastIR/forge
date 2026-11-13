#pragma once

#include "pe/image.h"

namespace forge {
    enum class RecordDefect { InvalidRecord, UnmappedCode };

    struct FunctionRange {
        RuntimeFunction record;
        std::vector<size_t> indices;
        bool entry = false, callback = false;
        std::optional<RecordDefect> defect;
        bool chainedFragment = false;
        std::optional<unsigned> unsupportedUnwindVersion;
        std::optional<size_t> overlapGroup;
        std::string name, file;
        unsigned line = 0;

        bool covered() const { return !defect && !overlapGroup && !unsupportedUnwindVersion; }

        bool eligible() const { return covered() && !chainedFragment; }
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
