#include "analysis/analysis.h"
#include "cli/report.h"
#include "diagnostic.h"
#include "lift/lift.h"
#include "output/publication.h"
#include "pe/dependencies.h"
#include "pe/input.h"

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"

#include <CLI11.hpp>

#include <algorithm>
#include <charconv>
#include <string_view>

namespace {
    using namespace forge;

    uint32_t parseRva(std::string_view value) {
        int base = 10;
        if (value.starts_with("0x") || value.starts_with("0X")) {
            value.remove_prefix(2);
            base = 16;
        }

        uint32_t rva;
        auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), rva, base);
        if (ec != std::errc{} || end != value.data() + value.size()) {
            throw std::invalid_argument("expected a 32-bit decimal or hexadecimal RVA");
        }

        return rva;
    }

    struct Options {
        std::string command;
        fs::path input, output;
        std::vector<fs::path> paths;
        uint32_t rva = 0;
        EntryMode entryMode = EntryMode::RegisterState;
        bool json = false, strict = false, verbose = false, jsonDiagnostics = false;
    };

    void addFormat(CLI::App &command, const char *name, bool &json, const char *description) {
        command
            .add_option_function<std::string>(
                name, [&json](const std::string &format) { json = format == "json"; }, description)
            ->check(CLI::IsMember({"text", "json"}))
            ->trigger_on_parse();
    }

    void configureCli(CLI::App &app, Options &options) {
        app.require_subcommand(1, 1);
        app.allow_windows_style_options(false);
        auto *inspectCommand =
            app.add_subcommand("inspect", "Inspect PE metadata and dependencies.");
        auto *analyzeCommand = app.add_subcommand("analyze", "Discover functions in a PE image.");
        auto *liftCommand = app.add_subcommand("lift", "Lift a discovered function to LLVM IR.");

        for (auto *command : {inspectCommand, analyzeCommand, liftCommand}) {
            command
                ->add_option<fs::path, std::string>(command == liftCommand ? "exe" : "image",
                                                    options.input, "Input PE image.")
                ->required();
        }

        for (auto *command : {inspectCommand, analyzeCommand}) {
            addFormat(*command, "--format", options.json, "Report format (default: text).");
            command->add_flag("--strict", options.strict, "Return exit 3 on strict findings.");
        }

        inspectCommand->add_flag("--verbose", options.verbose,
                                 "Include details in the text report.");
        inspectCommand
            ->add_option_function<std::string>(
                "--dll-path",
                [&options](const std::string &path) {
                    std::error_code ec;
                    auto dir = fs::canonical(path, ec);
                    if (ec || !fs::is_directory(dir, ec)) {
                        throw CLI::ValidationError("--dll-path",
                                                   "expected an existing directory: " + path);
                    }

                    options.paths.push_back(std::move(dir));
                },
                "Add a DLL search directory (repeatable, in search order).")
            ->type_name("DIR")
            ->trigger_on_parse();

        analyzeCommand->add_flag("--functions", "List discovered functions.")->required();
        liftCommand
            ->add_option_function<std::string>(
                "--rva", [&options](const std::string &value) { options.rva = parseRva(value); },
                "Function start as a decimal or hexadecimal RVA.")
            ->type_name("RVA")
            ->required()
            ->trigger_on_parse();
        liftCommand
            ->add_option<fs::path, std::string>("--output", options.output,
                                                "Destination LLVM IR file.")
            ->type_name("FILE")
            ->required()
            ->trigger_on_parse();
        liftCommand
            ->add_option_function<std::string>(
                "--signature",
                [&options](const std::string &) {
                    options.entryMode = EntryMode::WindowsX64I64Pair;
                },
                "Wrap the function with this signature (default: register state).")
            ->check(CLI::IsMember({"i64(i64,i64)"}))
            ->trigger_on_parse();
        addFormat(*liftCommand, "--diagnostics-format", options.jsonDiagnostics,
                  "Execution diagnostic format (default: text).");
    }

    std::string literalArgument(std::string arg) {
        // CLI11 decodes doubled brackets even in scalar arguments. Escape bracketed
        // argv strings with its matching encoder to keep file names byte-for-byte.
        CLI::detail::handle_secondary_array(arg);
        return arg;
    }

    std::vector<std::string> cliArguments(const CLI::App &app, int argc, char **argv) {
        if (argc < 2) {
            return {};
        }

        std::string name(argv[1]);
        if (app.get_help_ptr()->check_name(name)) {
            return {name};
        }

        const auto *command = app.get_subcommand_no_throw(name);
        if (!command) {
            throw CLI::ExtrasError({name});
        }

        // CLI11 splits attached values and treats ++ as a subcommand terminator.
        // Check the original option spelling and pass the input literally after --.
        std::vector<std::string> args{name};
        std::string input;
        bool literal = false;
        for (int i = 2; i < argc; ++i) {
            std::string arg(argv[i]);
            if (!literal && arg == "--") {
                literal = true;
                continue;
            }

            const bool positional = literal || !arg.starts_with('-');
            if (positional && !input.empty()) {
                throw CLI::ExtrasError({arg});
            }

            if (positional) {
                input = std::move(arg);
                continue;
            }

            const auto *option = command->get_option_no_throw(arg);
            if (!option) {
                throw CLI::ExtrasError({arg});
            }

            args.push_back(arg);
            if (option == command->get_help_ptr()) {
                break;
            }

            if (option->get_items_expected_max() == 0) {
                continue;
            }

            ++i;
            if (i == argc || !*argv[i] || std::string_view(argv[i]).starts_with("--")) {
                throw CLI::ValidationError(arg, "requires a value");
            }

            args.push_back(literalArgument(argv[i]));
        }

        if (!input.empty()) {
            args.emplace_back("--");
            args.push_back(literalArgument(std::move(input)));
        }

        // CLI11 expects its vector of arguments in reverse order.
        std::reverse(args.begin(), args.end());
        return args;
    }

    int execute(const Options &options) {
        const auto &input = options.input;
        const bool lifting = options.command == "lift";
        FailureCode unexpected = FailureCode::InputInternal;

        try {
            if (options.command == "inspect") {
                auto report = inspect(input, options.paths);
                printReport(report, options.json, options.verbose, llvm::outs());
                printDiagnostics(report, llvm::errs());
                return options.strict && report.strictFailure ? 3 : 0;
            }

            std::unique_ptr<ParsedImage> image;
            {
                InputFile file(input);
                unexpected = FailureCode::PeInternal;
                image = std::make_unique<ParsedImage>(file, ParsePolicy::FunctionAnalysis);
            }

            unexpected = FailureCode::AnalysisInternal;
            AnalyzedImage analysis(std::move(image), lifting ? DebugInfo::Omit : DebugInfo::Enrich);

            if (!lifting) {
                printAnalysis(analysis, options.json, llvm::outs());
                printFindings(analysis, input, llvm::errs());
                return options.strict && !analysis.findings().empty() ? 3 : 0;
            }

            unexpected = FailureCode::PublicationInternal;
            (void)checkedOutputDestination(analysis.image(), options.output);

            unexpected = FailureCode::LiftingInternal;
            llvm::LLVMContext context;
            auto module = generateIR(analysis, {options.rva, options.entryMode}, context);

            unexpected = FailureCode::PublicationInternal;
            publishIR(*module, analysis.image(), options.output);
            return 0;
        } catch (const InspectionError &error) {
            if (error.kind == FailureCode::OutputAlias) {
                throw std::invalid_argument(error.what());
            }

            if (options.jsonDiagnostics) {
                printLiftDiagnostic(error, input, options.rva, llvm::errs());
            } else {
                const auto prefix = failureKind(error.kind).legacy;
                if (prefix != "forge") {
                    llvm::errs() << input.string() << ": ";
                }

                llvm::errs() << prefix << ": " << error.what() << "\n";
            }

            return 1;
        } catch (const std::exception &error) {
            if (!options.jsonDiagnostics) {
                throw;
            }

            InspectionError failure(error.what(), unexpected);

            if (unexpected == FailureCode::PublicationInternal) {
                failure.context.output = options.output;
            }

            printLiftDiagnostic(failure, input, options.rva, llvm::errs());

            return 1;
        }
    }

    int run(int argc, char **argv) {
        Options parsed;
        CLI::App app("Inspect, analyze, and lift Windows PE images.", "forge");
        configureCli(app, parsed);

        try {
            app.parse(cliArguments(app, argc, argv));
            parsed.command = app.get_subcommands().front()->get_name();
            return execute(parsed);
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
