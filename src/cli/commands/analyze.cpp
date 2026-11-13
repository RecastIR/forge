#include "cli/commands/analyze.h"
#include "cli/analysis_input.h"
#include "cli/parsing.h"
#include "cli/report.h"

namespace forge::cli {
    namespace {
        int executeAnalyze(const AnalyzeOptions &options) {
            FailureCode stage = FailureCode::InputInternal;

            try {
                const auto analysis = analyzeInput(options.input, DebugInfo::Enrich, stage);
                printAnalysis(analysis, options.report.json, llvm::outs());
                printFindings(analysis, options.input, llvm::errs());
                return options.report.strict && !analysis.findings().empty() ? 3 : 0;
            } catch (const InspectionError &error) {
                printFailure(error, options.input, llvm::errs());
                return 1;
            }
        }
    } // namespace

    void registerAnalyze(CLI::App &app, AnalyzeOptions &options, int &status) {
        auto *command = app.add_subcommand("analyze", "Discover functions in a PE image.");
        addInput(*command, "image", options.input);
        addReportOptions(*command, options.report);
        command->add_flag("--functions", "List discovered functions.")->required();
        command->final_callback([&options, &status] { status = executeAnalyze(options); });
    }
} // namespace forge::cli
