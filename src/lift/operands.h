#pragma once

#include "lift/call_flow.h"
#include "lift/cfg.h"

namespace llvm {
    class MCRegisterInfo;
}

namespace forge::x86 {
    struct RegisterView {
        unsigned index, width, offset = 0;

        uint64_t writeMask() const { return width >= 32 ? UINT64_MAX : mask(); }

        uint64_t mask() const { return llvm::maskTrailingOnes<uint64_t>(width) << offset; }
    };

    struct AddressOperand {
        std::optional<RegisterView> base, index;
        uint64_t displacement, scale;
    };

    inline constexpr RegisterView stackPointer{rspIndex, 64};
    inline constexpr RegisterView framePointer{rspIndex + 1, 64};

    llvm::StringRef registerName(unsigned index);
    bool nonvolatile(unsigned index);
    enum class StackOp : uint8_t { PushRegister, PushImmediate, Pop, Leave };
    std::optional<StackOp> stackInstruction(llvm::StringRef opcode);
    std::optional<uint8_t> shiftCount(const Step &s, Form form);

    inline bool isNoop(llvm::StringRef opcode) { return opcode == "NOOPW" || opcode == "NOOPL"; }

    bool memoryDestination(Form form);
    unsigned memoryOperand(const Step &s, const IntegerInstruction &instruction);
    bool hasMemoryOperand(Form form);
    bool writesRegister(const IntegerInstruction &op);
    bool operandsCancel(const Step &s, const IntegerInstruction &instruction);

    // Analysis and emission interpret the same AMD64 operands at the selected guest base.
    class InstructionOperands {
      public:
        InstructionOperands(const llvm::MCRegisterInfo &regs, uint64_t guestBase)
            : regs(regs), guestBase(guestBase) {}

        RegisterView reg(const Step &s, const llvm::MCOperand &op, unsigned width) const;
        std::optional<uint64_t> ripAddress(const Step &s, unsigned first) const;
        AddressOperand decodeAddress(const Step &s, unsigned first, bool access) const;
        RegisterView destination(const Step &s, const IntegerInstruction &instruction) const;
        std::optional<RegisterView> resultRegister(const Step &s) const;

      private:
        const llvm::MCRegisterInfo &regs;
        uint64_t guestBase;
    };
} // namespace forge::x86
