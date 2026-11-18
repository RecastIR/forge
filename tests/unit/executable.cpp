#include "output/executable.h"
#include "analysis/analysis.h"
#include "lift/lift.h"

#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <string_view>

int main(int argc, char **argv) try {
    std::optional<uint64_t> guestBase;
    if (argc >= 4 && std::string_view(argv[1]) == "--guest-base") {
        uint64_t value;
        if (llvm::StringRef(argv[2]).getAsInteger(0, value)) {
            throw std::invalid_argument("invalid guest base");
        }

        guestBase = value;
        argc -= 2;
        argv += 2;
    }

    const bool object = argc == 6 && std::string_view(argv[2]) == "--object";

    if (argc != 2 && !object && argc < 9) {
        throw std::invalid_argument("expected PE [--object output opt llc | output opt llc xcrun "
                                    "startup runtime sdk flags...]");
    }

    forge::AnalyzedImage analysis(
        std::make_unique<forge::ParsedImage>(forge::InputFile(argv[1]),
                                             forge::ParsePolicy::FunctionAnalysis),
        forge::DebugInfo::Omit);
    llvm::LLVMContext context;
    forge::ExecutableReadiness readiness;
    const auto module = forge::generateExecutableIR(analysis, guestBase, context, readiness);

    if (argc == 2) {
        module->print(llvm::outs(), nullptr);
        return 0;
    }

    if (object) {
        forge::ExecutableToolchain tools;
        tools.opt = argv[4];
        tools.llc = argv[5];
        forge::publishNativeObject(*module, analysis.image(), argv[3], tools, true);
        return 0;
    }

    forge::ExecutableToolchain tools{argv[3], argv[4], argv[5], argv[6], argv[7], argv[8], {}};
    tools.linkFlags.assign(argv + 9, argv + argc);
    forge::publishExecutable(*module, analysis.image(), argv[2], tools, false);
} catch (const forge::InspectionError &error) {
    llvm::errs() << forge::failureKind(error.kind).code << ": " << error.what() << '\n';
    return 1;
} catch (const std::exception &error) {
    llvm::errs() << "executable contract: " << error.what() << '\n';
    return 1;
}
