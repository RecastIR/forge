#pragma once

#include "cli/report.h"

#include <filesystem>

namespace CLI {
    class App;
}

namespace forge::cli {
    struct AnalyzeOptions {
        std::filesystem::path input;
        ReportOptions report;
    };

    void registerAnalyze(CLI::App &app, AnalyzeOptions &options, int &status);
} // namespace forge::cli
