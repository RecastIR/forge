#include "cli/analysis_input.h"

namespace forge::cli {
    AnalyzedImage analyzeInput(const fs::path &input, DebugInfo debugInfo, FailureCode &stage) {
        std::unique_ptr<ParsedImage> image;
        {
            stage = FailureCode::InputInternal;
            InputFile file(input);
            stage = FailureCode::PeInternal;
            image = std::make_unique<ParsedImage>(file, ParsePolicy::FunctionAnalysis);
        }

        stage = FailureCode::AnalysisInternal;
        return AnalyzedImage(std::move(image), debugInfo);
    }
} // namespace forge::cli
