#include "cli/commands/inspect.h"
#include "cli/parsing.h"
#include "cli/report.h"
#include "diagnostic.h"
#include "pe/dependencies.h"

namespace forge::cli {
    namespace {
        int executeInspect(const InspectOptions &options) {
            try {
                const auto report = inspect(options.input, options.searchPaths);
                printReport(report, options.report.json, options.verbose, llvm::outs());
                printDiagnostics(report, llvm::errs());
                return options.report.strict && report.strictFailure ? 3 : 0;
            } catch (const InspectionError &error) {
                printFailure(error, options.input, llvm::errs());
                return 1;
            }
        }
    } // namespace

    void registerInspect(CLI::App &app, InspectOptions &options, int &status) {
        auto *command = app.add_subcommand("inspect", "Inspect PE metadata and dependencies.");
        addInput(*command, "image", options.input);
        addReportOptions(*command, options.report);
        command->add_flag("--verbose", options.verbose, "Include details in the text report.");
        command
            ->add_option_function<std::string>(
                "--dll-path",
                [&options](const std::string &path) {
                    std::error_code ec;
                    auto dir = fs::canonical(path, ec);

                    if (ec || !fs::is_directory(dir, ec)) {
                        throw CLI::ValidationError("--dll-path",
                                                   "expected an existing directory: " + path);
                    }

                    options.searchPaths.push_back(std::move(dir));
                },
                "Add a DLL search directory (repeatable, in search order).")
            ->type_name("DIR")
            ->trigger_on_parse();
        command->final_callback([&options, &status] { status = executeInspect(options); });
    }
} // namespace forge::cli
