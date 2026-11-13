#include "analysis/analysis.h"
#include "cli/report.h"
#include "diagnostic.h"
#include "lift/lift.h"
#include "output/publication.h"
#include "pe/dependencies.h"
#include "pe/input.h"

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"

#include <charconv>
#include <string_view>

namespace {
    using namespace forge;
    constexpr std::string_view usage =
        "Usage: forge inspect <image> [--dll-path <directory>]... [--format text|json] [--strict] "
        "[--verbose]\n"
        "       forge analyze <image> --functions [--format text|json] [--strict]\n"
        "       forge lift <exe> --rva <rva> [--signature 'i64(i64,i64)'] --output <file.ll> "
        "[--diagnostics-format text|json]\n";

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

    bool parseJsonFormat(std::string_view option, std::string_view value) {
        if (value != "text" && value != "json") {
            throw std::invalid_argument(std::string(option) + " must be text or json");
        }

        return value == "json";
    }

    struct Options {
        std::string_view command;
        fs::path input, output;
        std::vector<fs::path> paths;
        std::optional<uint32_t> rva;
        EntryMode entryMode = EntryMode::RegisterState;
        bool json = false, strict = false, verbose = false, functions = false;
        bool jsonDiagnostics = false;

        void parseOption(std::string_view arg, int &i, int argc, char **argv) {
            auto value = [&]() -> std::string_view {
                ++i;

                if (i == argc || !*argv[i] || std::string_view(argv[i]).starts_with("--")) {
                    throw std::invalid_argument(std::string(arg) + " requires a value");
                }

                return argv[i];
            };

            if (command != "lift" && arg == "--strict") {
                strict = true;
            } else if (command != "lift" && arg == "--format") {
                json = parseJsonFormat(arg, value());
            } else if (command == "inspect" && arg == "--dll-path") {
                fs::path path(value());
                std::error_code ec;
                auto dir = fs::canonical(path, ec);
                if (ec || !fs::is_directory(dir, ec)) {
                    throw std::invalid_argument("--dll-path must name an existing directory: " +
                                                path.string());
                }

                paths.push_back(std::move(dir));
            } else if (command == "inspect" && arg == "--verbose") {
                verbose = true;
            } else if (command == "analyze" && arg == "--functions") {
                functions = true;
            } else if (command == "lift" && arg == "--diagnostics-format") {
                jsonDiagnostics = parseJsonFormat(arg, value());
            } else if (command == "lift" && arg == "--rva") {
                rva = parseRva(value());
            } else if (command == "lift" && arg == "--output") {
                output = value();
            } else if (command == "lift" && arg == "--signature") {
                if (value() != "i64(i64,i64)") {
                    throw std::invalid_argument("unsupported signature; expected i64(i64,i64)");
                }

                entryMode = EntryMode::WindowsX64I64Pair;
            } else {
                throw std::invalid_argument("unknown option: " + std::string(arg));
            }
        }
    };

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
            auto module = generateIR(analysis, {options.rva.value(), options.entryMode}, context);

            unexpected = FailureCode::PublicationInternal;
            publishIR(*module, analysis.image(), options.output);
            return 0;
        } catch (const InspectionError &error) {
            if (error.kind == FailureCode::OutputAlias) {
                throw std::invalid_argument(error.what());
            }

            if (options.jsonDiagnostics) {
                printLiftDiagnostic(error, input, options.rva.value(), llvm::errs());
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

            printLiftDiagnostic(failure, input, options.rva.value(), llvm::errs());

            return 1;
        }
    }

    int run(int argc, char **argv) {
        Options parsed;
        parsed.command = argc < 2 ? "" : argv[1];
        const auto command = parsed.command;

        if (command == "--help") {
            llvm::outs() << usage;
            return 0;
        }

        if (command != "inspect" && command != "analyze" && command != "lift") {
            throw std::invalid_argument("expected inspect, analyze, or lift");
        }

        bool options = true;
        for (int i = 2; i < argc; ++i) {
            std::string_view arg = argv[i];
            if (options && arg == "--") {
                options = false;
            } else if (options && arg == "--help") {
                llvm::outs() << usage;
                return 0;
            } else if (options && arg.starts_with('-')) {
                parsed.parseOption(arg, i, argc, argv);
            } else if (!parsed.input.empty()) {
                throw std::invalid_argument(std::string(command) + " takes one input image");
            } else {
                parsed.input = arg;
            }
        }

        if (parsed.input.empty()) {
            throw std::invalid_argument("missing input image");
        }

        if (command == "analyze" && !parsed.functions) {
            throw std::invalid_argument("analyze requires --functions");
        }

        if (command == "lift" && (!parsed.rva || parsed.output.empty())) {
            throw std::invalid_argument("lift requires --rva and --output");
        }

        return execute(parsed);
    }
} // namespace

int main(int argc, char **argv) {
    try {
        return run(argc, argv);
    } catch (const std::invalid_argument &e) {
        llvm::errs() << "forge: " << e.what() << "\n" << usage;
        return 2;
    } catch (const std::exception &e) {
        llvm::errs() << "forge: " << e.what() << "\n";
        return 1;
    }
}
