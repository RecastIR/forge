#include "cli/commands/analyze.h"
#include "cli/commands/inspect.h"
#include "cli/commands/lift.h"
#include "cli/parsing.h"

#include "llvm/Support/raw_ostream.h"

namespace {
    using namespace forge::cli;

    int run(int argc, char **argv) {
        InspectOptions inspect;
        AnalyzeOptions analyze;
        LiftOptions lift;
        int status = 0;
        CLI::App app("Inspect, analyze, and lift Windows PE images.", "forge");
        app.require_subcommand(1, 1);
        app.allow_windows_style_options(false);
        registerInspect(app, inspect, status);
        registerAnalyze(app, analyze, status);
        registerLift(app, lift, status);

        try {
            app.parse(cliArguments(app, argc, argv));
            return status;
        } catch (const CLI::CallForHelp &) {
            llvm::outs() << app.help("Usage:");
            return 0;
        } catch (const CLI::ParseError &error) {
            llvm::errs() << "forge: " << error.what() << "\n" << app.help("Usage:");
        } catch (const std::invalid_argument &error) {
            llvm::errs() << "forge: " << error.what() << "\n" << app.help("Usage:");
        }

        return 2;
    }
} // namespace

int main(int argc, char **argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception &e) {
        llvm::errs() << "forge: " << e.what() << "\n";
        return 1;
    }
}
