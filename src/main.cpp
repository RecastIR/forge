#include "forge.h"

#include <string_view>

namespace {
using namespace forge;
constexpr std::string_view usage =
    "Usage: forge inspect <image> [--dll-path <directory>]... [--format text|json] [--strict]\n";

int run(int argc, char **argv) {
  if (argc == 2 && std::string_view(argv[1]) == "--help") {
    llvm::outs() << usage;
    return 0;
  }
  if (argc < 2 || std::string_view(argv[1]) != "inspect")
    throw std::invalid_argument("expected the inspect command");

  fs::path input;
  std::vector<fs::path> paths;
  bool json = false, strict = false, options = true;
  for (int i = 2; i < argc; ++i) {
    std::string_view arg = argv[i];
    if (options && arg == "--")
      options = false;
    else if (options && arg == "--help") {
      llvm::outs() << usage;
      return 0;
    } else if (options && arg == "--strict")
      strict = true;
    else if (options && (arg == "--format" || arg == "--dll-path")) {
      if (++i == argc || !*argv[i] || std::string_view(argv[i]).starts_with("--"))
        throw std::invalid_argument(std::string(arg) + " requires a value");
      std::string value = argv[i];
      if (arg == "--dll-path") {
        std::error_code ec;
        auto dir = fs::canonical(value, ec);
        if (ec || !fs::is_directory(dir, ec))
          throw std::invalid_argument("--dll-path must name an existing directory: " + value);
        paths.push_back(std::move(dir));
      } else {
        if (value != "text" && value != "json")
          throw std::invalid_argument("--format must be text or json");
        json = value == "json";
      }
    } else if (options && arg.starts_with("-"))
      throw std::invalid_argument("unknown option: " + std::string(arg));
    else if (!input.empty())
      throw std::invalid_argument("inspect takes one input image");
    else
      input = arg;
  }
  if (input.empty())
    throw std::invalid_argument("missing input image");
  try {
    auto report = inspect(input, paths);
    printReport(report, json, llvm::outs());
    printDiagnostics(report, llvm::errs());
    return strict && report.strictFailure ? 3 : 0;
  } catch (const InspectionError &e) {
    llvm::errs() << input.string() << ": " << e.code << ": " << e.what() << "\n";
    return 1;
  }
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
