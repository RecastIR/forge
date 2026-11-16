#include "lift/operands.h"

#include "llvm/ADT/StringSwitch.h"
#include "llvm/MC/MCRegisterInfo.h"

#include <string_view>

namespace forge::x86 {
    using namespace llvm;

    namespace {
        struct RegisterNames {
            StringLiteral wide, dword, word, lowByte, highByte;
        };

        // The first seven rows are the register-state ABI, in wire order.
        constexpr RegisterNames registerNames[] = {
            {"RAX", "EAX", "AX", "AL", "AH"},    {"RCX", "ECX", "CX", "CL", "CH"},
            {"RDX", "EDX", "DX", "DL", "DH"},    {"R8", "R8D", "R8W", "R8B", ""},
            {"R9", "R9D", "R9W", "R9B", ""},     {"R10", "R10D", "R10W", "R10B", ""},
            {"R11", "R11D", "R11W", "R11B", ""}, {"RSP", "ESP", "SP", "SPL", ""},
            {"RBP", "EBP", "BP", "BPL", ""},     {"RBX", "EBX", "BX", "BL", "BH"},
            {"RSI", "ESI", "SI", "SIL", ""},     {"RDI", "EDI", "DI", "DIL", ""},
            {"R12", "R12D", "R12W", "R12B", ""}, {"R13", "R13D", "R13W", "R13B", ""},
            {"R14", "R14D", "R14W", "R14B", ""}, {"R15", "R15D", "R15W", "R15B", ""}};
        static_assert(std::size(registerNames) == registerCount);
        static_assert(std::string_view(registerNames[rspIndex].wide) == "RSP");
        static_assert(std::string_view(registerNames[framePointer.index].wide) == "RBP");
    } // namespace

    StringRef registerName(unsigned index) { return registerNames[index].wide; }

    bool nonvolatile(unsigned index) { return index > rspIndex; }

    std::optional<StackOp> stackInstruction(StringRef opcode) {
        return StringSwitch<std::optional<StackOp>>(opcode)
            .Cases({"PUSH64r", "PUSH64rmr"}, StackOp::PushRegister)
            .Cases({"PUSH64i8", "PUSH64i32"}, StackOp::PushImmediate)
            .Cases({"POP64r", "POP64rmr"}, StackOp::Pop)
            .Case("LEAVE64", StackOp::Leave)
            .Default(std::nullopt);
    }

    std::optional<uint8_t> shiftCount(const Step &s, Form form) {
        if (form == Form::ShiftOne) {
            return 1U;
        }

        if (form == Form::ShiftImmediate) {
            return static_cast<uint8_t>(s.inst.getOperand(s.inst.getNumOperands() - 1).getImm());
        }

        return {};
    }

    RegisterView InstructionOperands::reg(const Step &s, const MCOperand &op,
                                          unsigned width) const {
        if (!op.isReg() || !op.getReg()) {
            s.reject(FailureCode::UnsupportedRegister, "expected a general-purpose register");
        }

        auto name = StringRef(regs.getName(op.getReg()));

        for (unsigned index = 0; index < std::size(registerNames); ++index) {
            const auto &names = registerNames[index];

            if ((width == 64 && names.wide == name) || (width == 32 && names.dword == name) ||
                (width == 16 && names.word == name) || (width == 8 && names.lowByte == name)) {
                return {index, width};
            }

            if (width == 8 && names.highByte == name) {
                return {index, width, 8};
            }
        }

        s.reject(FailureCode::UnsupportedRegister, "unsupported register " + name);
    }

    std::optional<uint64_t> InstructionOperands::ripAddress(const Step &s, unsigned first) const {
        const auto base = s.inst.getOperand(first).getReg();

        if (!base || StringRef(regs.getName(base)) != "RIP") {
            return {};
        }

        const auto displacement = s.inst.getOperand(first + 3).getImm();
        const auto signedOffset = llvm::SignExtend64<32>(static_cast<uint64_t>(displacement));
        return guestBase + s.next + static_cast<uint64_t>(signedOffset);
    }

    AddressOperand InstructionOperands::decodeAddress(const Step &s, unsigned first,
                                                      bool access) const {
        const auto &inst = s.inst;
        const auto &base = inst.getOperand(first);
        const auto scale = inst.getOperand(first + 1).getImm();
        const auto &index = inst.getOperand(first + 2);
        const auto displacement = inst.getOperand(first + 3).getImm();
        const auto segment = inst.getOperand(first + 4).getReg();
        const bool hasIndex = index.getReg() && StringRef(regs.getName(index.getReg())) != "RIZ";

        if (segment || (scale != 1 && scale != 2 && scale != 4 && scale != 8)) {
            s.reject(FailureCode::UnsupportedInstruction, "unsupported segment or address scale");
        }

        if (auto rip = ripAddress(s, first)) {
            if (hasIndex || scale != 1) {
                s.reject(FailureCode::UnsupportedInstruction,
                         "invalid indexed RIP-relative operand");
            }

            return {{}, {}, *rip, 1};
        }

        if (access && !base.getReg() && !hasIndex) {
            s.reject(FailureCode::UnsupportedInstruction, "absolute memory operand");
        }

        AddressOperand operand{
            {}, {}, static_cast<uint64_t>(displacement), static_cast<uint64_t>(scale)};

        if (base.getReg()) {
            operand.base = reg(s, base, 64);
        }

        if (hasIndex) {
            operand.index = reg(s, index, 64);
        }

        return operand;
    }

    void InstructionOperands::validateIntegerOperands(const Step &s,
                                                      const IntegerInstruction &op) const {
        const unsigned count = s.inst.getNumOperands();
        const unsigned address = hasMemoryOperand(op.form) ? memoryOperand(s, op) : count;

        for (unsigned i = 0; i < count; ++i) {
            if (i == address) {
                decodeAddress(s, i, true);
                i += 4; // The address tuple occupies five MC operands.
            } else if (s.inst.getOperand(i).isReg()) {
                reg(s, s.inst.getOperand(i), i == 0 ? op.width : op.sourceWidth);
            }
        }
    }

    RegisterView InstructionOperands::destination(const Step &s,
                                                  const IntegerInstruction &instruction) const {
        if (instruction.form == Form::Accumulator) {
            return {0, instruction.width};
        }

        return reg(s, s.inst.getOperand(0), instruction.width);
    }

    std::optional<RegisterView> InstructionOperands::resultRegister(const Step &s) const {
        if (s.opcode == "CWDE" || s.opcode == "CDQE") {
            return RegisterView{0, s.opcode == "CWDE" ? 32U : 64U};
        }

        if (s.opcode == "LAHF") {
            return RegisterView{0, 8, 8};
        }

        unsigned width = 0;

        if (s.opcode == "LEA64r" || s.opcode == "CMOV64rr") {
            width = 64;
        } else if (s.opcode == "LEA64_32r" || s.opcode == "CMOV32rr") {
            width = 32;
        } else if (s.opcode == "CMOV16rr") {
            width = 16;
        } else if (s.opcode == "SETCCr") {
            width = 8;
        } else {
            return {};
        }

        return reg(s, s.inst.getOperand(0), width);
    }

    bool memoryDestination(Form form) {
        return form == Form::MemoryImmediate || form == Form::MemoryRegister ||
               form == Form::MemoryUnary || form == Form::Store;
    }

    unsigned memoryOperand(const Step &s, const IntegerInstruction &instruction) {
        // In register-destination arithmetic, the output and tied input precede the tuple.
        return memoryDestination(instruction.form) ? 0 : s.inst.getNumOperands() - 5;
    }

    bool hasMemoryOperand(Form form) { return memoryDestination(form) || form == Form::Load; }

    bool writesRegister(const IntegerInstruction &op) {
        return !memoryDestination(op.form) && op.op != Op::Cmp && op.op != Op::Test;
    }

    bool operandsCancel(const Step &s, const IntegerInstruction &instruction) {
        const auto op = instruction.op;
        const auto &last = s.inst.getOperand(s.inst.getNumOperands() - 1);
        return instruction.form == Form::Pair &&
               (op == Op::Xor || op == Op::Sub || op == Op::Cmp || op == Op::Sbb) &&
               s.inst.getOperand(0).getReg() == last.getReg();
    }
} // namespace forge::x86
