#pragma once

#include "lift/operands.h"
#include "pe/image.h"

namespace forge::x86 {
    // Recovery uses RVAs throughout. Relative entries require no load-base-dependent fixups.
    class JumpTableReader {
      public:
        JumpTableReader(const ParsedImage &image, const llvm::MCRegisterInfo &regs)
            : image(image), operands(regs, 0) {}

        RelativeTable recognize(const std::map<uint32_t, Step> &decoded, const Step &jump) const;
        llvm::SmallVector<uint32_t, 2> targets(const Step &jump, RelativeTable table,
                                               RvaRange function);

      private:
        const ParsedImage &image;
        InstructionOperands operands;
        std::optional<ImageInitialization> initialization;
    };
} // namespace forge::x86
