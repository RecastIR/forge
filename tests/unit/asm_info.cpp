#include "lift/asm_info.h"

#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/raw_ostream.h"

#include <exception>
#include <type_traits>

using namespace llvm;
using forge::x86::createAsmInfo;

static_assert(!std::is_invocable_v<decltype(createAsmInfo), const Target &, const MCRegisterInfo &,
                                   const Triple &, MCTargetOptions &&>);

int main() try {
    LLVMInitializeX86TargetInfo();
    LLVMInitializeX86TargetMC();
    const Triple Guest("x86_64-pc-windows-msvc");
    std::string Error;
    const auto *Target = TargetRegistry::lookupTarget(Guest, Error);
    if (!Target) {
        errs() << Error << '\n';
        return 1;
    }
    std::unique_ptr<MCRegisterInfo> Registers(Target->createMCRegInfo(Guest));
    if (!Registers) {
        errs() << "X86 register info unavailable\n";
        return 1;
    }

    MCTargetOptions Options;
    Options.OutputAsmVariant = 1;
    auto Assembly = createAsmInfo(*Target, *Registers, Guest, Options);
    if (!Assembly || &Assembly->getTargetOptions() != &Options) {
        errs() << "X86 assembly info must borrow the caller's target options\n";
        return 1;
    }
    if (Assembly->getOutputAssemblerDialect() != *Options.OutputAsmVariant) {
        errs() << "X86 assembly info ignored the selected output dialect\n";
        return 1;
    }
} catch (const std::exception &Error) {
    errs() << "X86 assembly info: " << Error.what() << '\n';
    return 1;
}
