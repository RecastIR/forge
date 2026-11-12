#include "analysis/analysis.h"
#include "pe/input.h"

#include <charconv>
#include <string_view>

namespace {
using namespace forge;
constexpr std::string_view usage =
    "Usage: forge inspect <image> [--dll-path <directory>]... [--format text|json] [--strict] "
    "[--verbose]\n"
    "       forge analyze <image> --functions [--format text|json] [--strict]\n"
    "       forge lift <exe> --rva <rva> [--signature 'i64(i64,i64)'] --output <file.ll>\n";

uint32_t parseRva(std::string_view value) {
    int base = 10;
    if (value.starts_with("0x") || value.starts_with("0X")) {
        value.remove_prefix(2);
        base = 16;
    }
    uint32_t rva;
    auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), rva, base);
    if (ec != std::errc{} || end != value.data() + value.size())
        throw std::invalid_argument("expected a 32-bit decimal or hexadecimal RVA");
    return rva;
}

int run(int argc, char** argv) {
    const std::string_view command = argc < 2 ? "" : argv[1];
    if (command == "--help") {
        llvm::outs() << usage;
        return 0;
    }
    if (command != "inspect" && command != "analyze" && command != "lift")
        throw std::invalid_argument("expected inspect, analyze, or lift");

    fs::path input, output;
    std::vector<fs::path> paths;
    std::optional<uint32_t> rva;
    bool json = false, strict = false, verbose = false, functions = false, wrapper = false;
    auto parseOption = [&](std::string_view arg, int& i) {
        auto value = [&]() -> std::string_view {
            if (++i == argc || !*argv[i] || std::string_view(argv[i]).starts_with("--"))
                throw std::invalid_argument(std::string(arg) + " requires a value");
            return argv[i];
        };
        if (command != "lift" && arg == "--strict")
            strict = true;
        else if (command != "lift" && arg == "--format") {
            auto format = value();
            if (format != "text" && format != "json")
                throw std::invalid_argument("--format must be text or json");
            json = format == "json";
        } else if (command == "inspect" && arg == "--dll-path") {
            fs::path path(value());
            std::error_code ec;
            auto dir = fs::canonical(path, ec);
            if (ec || !fs::is_directory(dir, ec))
                throw std::invalid_argument("--dll-path must name an existing directory: " +
                                            path.string());
            paths.push_back(std::move(dir));
        } else if (command == "inspect" && arg == "--verbose")
            verbose = true;
        else if (command == "analyze" && arg == "--functions")
            functions = true;
        else if (command == "lift" && arg == "--rva")
            rva = parseRva(value());
        else if (command == "lift" && arg == "--output")
            output = value();
        else if (command == "lift" && arg == "--signature") {
            if (value() != "i64(i64,i64)")
                throw std::invalid_argument("unsupported signature; expected i64(i64,i64)");
            wrapper = true;
        } else
            throw std::invalid_argument("unknown option: " + std::string(arg));
    };
    bool options = true;
    for (int i = 2; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (options && arg == "--")
            options = false;
        else if (options && arg == "--help") {
            llvm::outs() << usage;
            return 0;
        } else if (options && arg.starts_with("-")) {
            parseOption(arg, i);
        } else if (!input.empty())
            throw std::invalid_argument(std::string(command) + " takes one input image");
        else
            input = arg;
    }
    if (input.empty())
        throw std::invalid_argument("missing input image");
    if (command == "analyze" && !functions)
        throw std::invalid_argument("analyze requires --functions");
    if (command == "lift" && (!rva || output.empty()))
        throw std::invalid_argument("lift requires --rva and --output");
    try {
        if (command == "inspect") {
            auto report = inspect(input, paths);
            printReport(report, json, verbose, llvm::outs());
            printDiagnostics(report, llvm::errs());
            return strict && report.strictFailure ? 3 : 0;
        }
        auto buffer = InputFile(input).read();
        auto analysis = analyzePE(buffer->getMemBufferRef(), command == "analyze");
        if (command == "lift") {
            std::error_code ec;
            if (fs::equivalent(input, output, ec))
                throw std::invalid_argument("--output must differ from the input image");
            lift(analysis, buffer->getMemBufferRef(), *rva, wrapper, output);
            return 0;
        }
        printAnalysis(analysis, json, llvm::outs());
        for (const auto& d : analysis.findings) {
            llvm::errs() << input.string() << ": " << d.code << ": " << d.message << " (records";
            for (auto i : d.records)
                llvm::errs() << " " << i;
            llvm::errs() << ")\n";
        }
        return strict && !analysis.findings.empty() ? 3 : 0;
    } catch (const InspectionError& e) {
        llvm::errs() << input.string() << ": " << e.code << ": " << e.what() << "\n";
        return 1;
    }
}
} // namespace

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::invalid_argument& e) {
        llvm::errs() << "forge: " << e.what() << "\n" << usage;
        return 2;
    } catch (const std::exception& e) {
        llvm::errs() << "forge: " << e.what() << "\n";
        return 1;
    }
}
