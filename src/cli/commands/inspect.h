#pragma once

#include "cli/report.h"

#include <filesystem>
#include <vector>

namespace CLI {
    class App;
}

namespace forge::cli {
    struct InspectOptions {
        std::filesystem::path input;
        std::vector<std::filesystem::path> searchPaths;
        ReportOptions report;
        bool verbose = false;
    };

    void registerInspect(CLI::App &app, InspectOptions &options, int &status);
} // namespace forge::cli
