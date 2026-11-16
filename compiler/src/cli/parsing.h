#pragma once

#include "cli/report.h"

#include <CLI/CLI.hpp>

#include <filesystem>
#include <string>
#include <vector>

namespace forge::cli {
    void addInput(CLI::App &command, const char *name, std::filesystem::path &input);
    void addFormat(CLI::App &command, const char *name, bool &json, const char *description);
    void addReportOptions(CLI::App &command, ReportOptions &options);
    std::vector<std::string> cliArguments(const CLI::App &app, int argc, char **argv);
} // namespace forge::cli
