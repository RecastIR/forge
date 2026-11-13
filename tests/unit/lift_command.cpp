#include "cli/commands/lift.h"

#include "llvm/ADT/ScopeExit.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"

namespace {
    std::string readIR(const std::filesystem::path &path) {
        const auto buffer = llvm::MemoryBuffer::getFile(path.native());

        if (!buffer) {
            throw std::system_error(buffer.getError());
        }

        return (*buffer)->getBuffer().str();
    }
} // namespace

int main(int argc, char **argv) try {
    if (argc != 2) {
        throw std::invalid_argument("expected the add.exe fixture");
    }

    llvm::SmallString<128> directory;

    if (auto error = llvm::sys::fs::createUniqueDirectory("forge-lift-command", directory)) {
        throw std::system_error(error);
    }

    llvm::scope_exit cleanup([&] {
        if (auto error = llvm::sys::fs::remove_directories(directory)) {
            llvm::errs() << "removing " << directory << ": " << error.message() << '\n';
        }
    });
    forge::cli::LiftOptions options;
    options.input = argv[1];
    options.output = std::filesystem::path(directory.c_str()) / "function.ll";
    options.request.startRva = 0x1000;
    options.jsonDiagnostics = true;
    std::string diagnostic;
    llvm::raw_string_ostream err(diagnostic);

    if (forge::cli::executeLift(options, err) != 0 || !diagnostic.empty()) {
        throw std::runtime_error("lift did not succeed silently: " + diagnostic);
    }

    const auto ir = readIR(options.output);

    if (ir.find("@forge_lifted_1000(") == std::string::npos) {
        throw std::runtime_error("missing lifted function");
    }

    options.request.startRva += 1;

    if (forge::cli::executeLift(options, err) != 1 || readIR(options.output) != ir) {
        throw std::runtime_error("invalid entry must fail and preserve the previous IR");
    }

    auto parsed = llvm::json::parse(diagnostic);

    if (!parsed) {
        throw std::runtime_error(llvm::toString(parsed.takeError()));
    }

    const auto *object = parsed->getAsObject();
    const auto *context = object ? object->getObject("context") : nullptr;

    if (!context || object->getString("code") != "ENTRY_INVALID_START" ||
        context->getString("entry_rva") != "0x1001" ||
        context->getString("input") != options.input.native()) {
        throw std::runtime_error("incorrect lift diagnostic: " + diagnostic);
    }
} catch (const std::exception &error) {
    llvm::errs() << "lift command: " << error.what() << '\n';
    return 1;
}
