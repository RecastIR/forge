#ifndef FORGE_LIFT_ASM_INFO_H
#define FORGE_LIFT_ASM_INFO_H

#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/TargetRegistry.h"

#include <functional>
#include <memory>

namespace forge::x86 {
    // LLVM retains options by reference for the lifetime of the returned assembly info.
    inline std::unique_ptr<llvm::MCAsmInfo>
    createAsmInfo(const llvm::Target &target, const llvm::MCRegisterInfo &registers,
                  const llvm::Triple &triple,
                  std::reference_wrapper<const llvm::MCTargetOptions> options) {
        return std::unique_ptr<llvm::MCAsmInfo>(
            target.createMCAsmInfo(registers, triple, options.get()));
    }
} // namespace forge::x86

#endif
