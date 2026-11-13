#ifndef FORGE_LIFT_ASM_INFO_H
#define FORGE_LIFT_ASM_INFO_H

#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/TargetRegistry.h"

#include <functional>
#include <memory>

namespace forge::x86 {
// LLVM retains Options by reference for the lifetime of the returned assembly info.
inline std::unique_ptr<llvm::MCAsmInfo>
createAsmInfo(const llvm::Target &Target, const llvm::MCRegisterInfo &Registers,
              const llvm::Triple &Triple,
              std::reference_wrapper<const llvm::MCTargetOptions> Options) {
    return std::unique_ptr<llvm::MCAsmInfo>(
        Target.createMCAsmInfo(Registers, Triple, Options.get()));
}
} // namespace forge::x86

#endif
