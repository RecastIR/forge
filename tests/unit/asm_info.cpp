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
    const Triple guest("x86_64-pc-windows-msvc");
    std::string error;
    const auto *target = TargetRegistry::lookupTarget(guest, error);
    if (!target) {
        errs() << error << '\n';
        return 1;
    }
    std::unique_ptr<MCRegisterInfo> registers(target->createMCRegInfo(guest));
    if (!registers) {
        errs() << "X86 register info unavailable\n";
        return 1;
    }

    MCTargetOptions options;
    options.OutputAsmVariant = 1;
    auto assembly = createAsmInfo(*target, *registers, guest, options);
    if (!assembly || &assembly->getTargetOptions() != &options) {
        errs() << "X86 assembly info must borrow the caller's target options\n";
        return 1;
    }
    if (assembly->getOutputAssemblerDialect() != *options.OutputAsmVariant) {
        errs() << "X86 assembly info ignored the selected output dialect\n";
        return 1;
    }
} catch (const std::exception &error) {
    errs() << "X86 assembly info: " << error.what() << '\n';
    return 1;
}
