#pragma once

#include "analysis/analysis.h"
#include "diagnostic.h"

namespace forge::cli {
    // On an unclassified exception, stage identifies the operation that was in progress.
    AnalyzedImage analyzeInput(const fs::path &input, DebugInfo debugInfo, FailureCode &stage);
} // namespace forge::cli
