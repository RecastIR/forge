#include "lift/lift.h"

#include "analysis/analysis.h"
#include "diagnostic.h"
#include "lift/asm_info.h"
#include "lift/cfg.h"
#include "lift/image_memory.h"
#include "lift/integer.h"
#include "lift/memory.h"

#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <array>
#include <deque>
#include <map>
#include <mutex>
#include <string_view>

namespace forge {
    namespace {
        using namespace llvm;

        InspectionError atRva(FailureCode kind, uint32_t rva, const Twine &why) {
            return InspectionError(hex(rva) + ": " + why.str(), kind);
        }

        using x86::Step;
        using x86::StoredValue;

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
        constexpr unsigned callerSlots = 7;
        constexpr unsigned rspIndex = callerSlots;
        static_assert(std::string_view(registerNames[rspIndex].wide) == "RSP");

        // The signatureless ABI accepts a four-byte-aligned register array.
        constexpr auto registerStateAlignment = Align::Constant<4>();

        struct RegisterView {
            unsigned index, width, offset = 0;

            uint64_t writeMask() const { return width >= 32 ? UINT64_MAX : mask(); }

            uint64_t mask() const { return maskTrailingOnes<uint64_t>(width) << offset; }
        };

        struct AddressOperand {
            std::optional<RegisterView> base, index;
            uint64_t displacement, scale;
        };

        constexpr RegisterView stackPointer{rspIndex, 64};
        constexpr RegisterView framePointer{rspIndex + 1, 64};
        static_assert(std::string_view(registerNames[framePointer.index].wide) == "RBP");

        bool nonvolatile(unsigned index) { return index > rspIndex; }

        // Every byte of every incoming nonvolatile has its own identity, distinct
        // from the uninitialized and concrete marks used by the guest stack.
        uint64_t entryMarks(unsigned index) {
            if (!nonvolatile(index)) {
                return UINT64_MAX;
            }

            uint64_t marks = 0;

            for (unsigned byte = 0; byte < 8; ++byte) {
                auto identity = (index - framePointer.index) * 8 + byte + 1;
                marks |= static_cast<uint64_t>(identity) << (8 * byte);
            }

            return marks;
        }

        enum class StackOp : uint8_t { PushRegister, PushImmediate, Pop, Leave };

        std::optional<StackOp> stackInstruction(StringRef opcode) {
            return StringSwitch<std::optional<StackOp>>(opcode)
                .Cases({"PUSH64r", "PUSH64rmr"}, StackOp::PushRegister)
                .Cases({"PUSH64i8", "PUSH64i32"}, StackOp::PushImmediate)
                .Cases({"POP64r", "POP64rmr"}, StackOp::Pop)
                .Case("LEAVE64", StackOp::Leave)
                .Default(std::nullopt);
        }

        using Defined = std::array<uint64_t, std::size(registerNames)>;

        // The offset is relative to entry RSP only for a Stack fact. Arithmetic
        // uses the same modulo-2^64 representation as guest address lowering.
        struct AddressFact {
            enum Kind { Unknown, Constant, Stack } kind = Unknown;

            uint64_t offset = 0;
            bool operator==(const AddressFact &) const = default;

            AddressFact plus(AddressFact rhs) const {
                if (kind == Unknown || rhs.kind == Unknown ||
                    (kind == Stack && rhs.kind == Stack)) {
                    return {};
                }

                return {kind == Stack || rhs.kind == Stack ? Stack : Constant, offset + rhs.offset};
            }
        };

        using AddressFacts = std::array<AddressFact, std::size(registerNames)>;

        struct Availability {
            Defined registers{};
            x86::FlagSet flags;
            AddressFacts addresses{};

            bool intersect(const Availability &other) {
                auto before = *this;
                flags &= other.flags;
                for (size_t i = 0; i < registers.size(); ++i) {
                    registers[i] &= other.registers[i];
                    if (addresses[i] != other.addresses[i]) {
                        addresses[i] = {};
                    }
                }

                return registers != before.registers || flags != before.flags ||
                       addresses != before.addresses;
            }
        };

        struct BlockState {
            Defined writes{};
            x86::FlagEffect flags{{}, x86::FlagSet().set()};
            Availability incoming;
            BasicBlock *irBlock = nullptr;
            BasicBlock *exitBlock = nullptr;
            std::array<PHINode *, x86::FlagCount> phis{};
            x86::Flags outgoing{};
            bool reached = false, queued = false;

            Availability transfer() const {
                auto result = incoming;
                result.flags = flags.apply(result.flags);
                for (size_t i = 0; i < writes.size(); ++i) {
                    result.registers[i] |= writes[i];
                }

                return result;
            }
        };

        using BlockStates = std::map<uint32_t, BlockState>;

        std::optional<uint8_t> shiftCount(const Step &s, x86::Form form) {
            if (form == x86::Form::ShiftOne) {
                return 1U;
            }

            if (form == x86::Form::ShiftImmediate) {
                return static_cast<uint8_t>(
                    s.inst.getOperand(s.inst.getNumOperands() - 1).getImm());
            }

            return {};
        }

        class Translator {
          public:
            Translator(llvm::Module &module, uint32_t rva, EntryMode mode,
                       const MCRegisterInfo &regs, x86::ImageMemory &image)
                : ir(module.getContext()), semantics(ir), memory(ir), imageMemory(image),
                  regs(regs), mode(mode) {
                auto *type = FunctionType::get(ir.getVoidTy(), ir.getPtrTy(), false);
                impl = Function::Create(type, Function::InternalLinkage,
                                        "forge_lifted_" + utohexstr(rva, true), module);
                impl->getArg(0)->setName("state");
                appendToUsed(module, {impl});
                auto *stateType = ArrayType::get(ir.getInt64Ty(), callerSlots);

                if (mode == EntryMode::WindowsX64I64Pair) {
                    auto *nativeType = FunctionType::get(ir.getInt64Ty(),
                                                         {ir.getInt64Ty(), ir.getInt64Ty()}, false);
                    auto *native = Function::Create(nativeType, Function::ExternalLinkage,
                                                    "forge_lifted", module);
                    ir.SetInsertPoint(BasicBlock::Create(module.getContext(), "entry", native));
                    auto *state = ir.CreateAlloca(stateType);
                    // Backing bits for partial writes must be concrete. Read eligibility is
                    // proved separately, so these zeros are never exposed as incoming values.
                    ir.CreateStore(ConstantAggregateZero::get(stateType), state);
                    ir.CreateStore(native->getArg(0), slot(state, 1));
                    ir.CreateStore(native->getArg(1), slot(state, 2));
                    ir.CreateCall(impl, state);
                    ir.CreateRet(ir.CreateLoad(ir.getInt64Ty(), slot(state, 0)));
                }
            }

            void translate(const x86::ControlFlowGraph &graph);

          private:
            IRBuilder<> ir;
            x86::IntegerSemantics semantics;
            x86::GuestMemory memory;
            x86::ImageMemory &imageMemory;
            const MCRegisterInfo &regs;
            EntryMode mode;
            Function *impl;
            Value *localRegisters = nullptr;
            bool accessesMemory = false;
            DenseSet<uint32_t> stackAccesses;
            bool tracksOrigins = false;
            std::bitset<std::size(registerNames)> modified;
            Value *registerMarks = nullptr;
            std::array<Value *, std::size(registerNames)> entryValues{};
            Defined defined{};

            Value *slot(Value *state, unsigned index) {
                if (index >= callerSlots) {
                    return ir.CreateInBoundsGEP(ir.getInt64Ty(), localRegisters,
                                                ir.getInt32(index - callerSlots));
                }

                return ir.CreateInBoundsGEP(ir.getInt64Ty(), state, ir.getInt32(index));
            }

            RegisterView reg(const Step &s, const MCOperand &operand, unsigned width) const;
            void initializeRegisters();
            void emitReturn(const Step &s);
            void checkReturnRegisters(const Step &s);
            void lowerStack(const Step &s, StackOp op);
            void recordWrite(BlockState &state, RegisterView view);
            Value *markSlot(unsigned index);
            Value *loadView(Value *ptr, RegisterView view);
            void storeView(Value *ptr, RegisterView view, Value *value, uint64_t upper);
            StoredValue readSaved(const Step &s, RegisterView view, bool allowIncoming);
            void writeSaved(RegisterView view, StoredValue value);
            Value *read(const Step &s, RegisterView view);
            Value *value(const Step &s, const MCOperand &operand, unsigned width);
            void write(RegisterView view, Value *v);
            Value *require(const Step &s, x86::Flag flag) const;
            Value *condition(const Step &s);
            void move(const Step &s, const x86::IntegerInstruction &instruction);
            void memoryArithmetic(const Step &s, const x86::IntegerInstruction &instruction);
            void integer(const Step &s, const x86::IntegerInstruction &instruction);
            void lower(const Step &s);
            std::optional<uint64_t> ripAddress(const Step &s, unsigned first) const;
            AddressOperand decodeAddress(const Step &s, unsigned first, bool access) const;
            Value *effectiveAddress(const Step &s, unsigned first, bool access);
            RegisterView destination(const Step &s,
                                     const x86::IntegerInstruction &instruction) const;
            std::optional<RegisterView> resultRegister(const Step &s) const;
            void requireMemory(const Step &s);
            void planMemoryAccess(const Step &s, const x86::IntegerInstruction &op,
                                  const AddressFacts &facts);
            void traceStackInstruction(const Step &s, StackOp op, AddressFacts &facts) const;
            AddressFact integerFact(const Step &s, const x86::IntegerInstruction &op,
                                    RegisterView dest, const AddressFacts &facts) const;
            void traceAddresses(const x86::GuestBlock &block, AddressFacts &facts, bool collect);
            void proveAvailability(const x86::ControlFlowGraph &graph, BlockStates &states);
            void summarize(const Step &s, BlockState &state);
            void emitBlock(const x86::GuestBlock &block, const BlockStates &states);
        };

        RegisterView Translator::reg(const Step &s, const MCOperand &op, unsigned width) const {
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

        Value *Translator::markSlot(unsigned index) {
            return ir.CreateInBoundsGEP(ir.getInt64Ty(), registerMarks, ir.getInt32(index));
        }

        Value *Translator::loadView(Value *ptr, RegisterView view) {
            auto *parent = ir.CreateAlignedLoad(ir.getInt64Ty(), ptr, registerStateAlignment);
            Value *bits = view.offset ? ir.CreateLShr(parent, view.offset) : parent;
            return ir.CreateTruncOrBitCast(bits, ir.getIntNTy(view.width));
        }

        StoredValue Translator::readSaved(const Step &s, RegisterView view, bool allowIncoming) {
            if (!(allowIncoming && nonvolatile(view.index)) &&
                (defined[view.index] & view.mask()) != view.mask()) {
                s.reject(FailureCode::UndefinedRegister,
                         "read of undefined incoming " + registerNames[view.index].wide);
            }

            return {loadView(slot(impl->getArg(0), view.index), view),
                    tracksOrigins ? loadView(markSlot(view.index), view) : nullptr};
        }

        Value *Translator::read(const Step &s, RegisterView view) {
            auto saved = readSaved(s, view, false);

            if (saved.marks) {
                memory.guard(ir.CreateICmpEQ(saved.marks,
                                             ConstantInt::getAllOnesValue(saved.marks->getType())));
            }

            return saved.bits;
        }

        Value *Translator::value(const Step &s, const MCOperand &op, unsigned width) {
            if (op.isImm()) {
                return ConstantInt::getSigned(ir.getIntNTy(width), op.getImm());
            }

            return read(s, reg(s, op, width));
        }

        void Translator::storeView(Value *ptr, RegisterView view, Value *v, uint64_t upper) {
            auto *result = ir.CreateZExtOrBitCast(v, ir.getInt64Ty());

            if (view.width < 32) {
                auto *parent = ir.CreateAlignedLoad(ir.getInt64Ty(), ptr, registerStateAlignment);
                result = ir.CreateOr(ir.CreateAnd(parent, ~view.mask()),
                                     ir.CreateShl(result, view.offset));
            } else if (view.width == 32 && upper) {
                result = ir.CreateOr(result, upper);
            }

            ir.CreateAlignedStore(result, ptr, registerStateAlignment);
        }

        void Translator::writeSaved(RegisterView view, StoredValue value) {
            storeView(slot(impl->getArg(0), view.index), view, value.bits, 0);

            if (tracksOrigins) {
                auto *marks =
                    value.marks ? value.marks : ConstantInt::getAllOnesValue(value.bits->getType());
                // A doubleword write supplies four concrete zero bytes above its result.
                storeView(markSlot(view.index), view, marks, 0xffffffff00000000ULL);
            }

            defined[view.index] |= view.writeMask();
        }

        void Translator::write(RegisterView view, Value *v) { writeSaved(view, {v}); }

        Value *Translator::require(const Step &s, x86::Flag flag) const {
            if (!semantics.flags[flag]) {
                s.reject(FailureCode::UndefinedFlag,
                         "unsupported use of undefined condition flags: " + x86::flagNames[flag]);
            }

            return semantics.flags[flag];
        }

        Value *Translator::condition(const Step &s) {
            auto code = s.inst.getOperand(s.inst.getNumOperands() - 1).getImm();

            if (code < 0 || code > 15) {
                s.reject(FailureCode::UnsupportedInstruction, "unsupported condition code");
            }

            return semantics.condition(static_cast<unsigned>(code),
                                       [&](x86::Flag f) { return require(s, f); });
        }

        std::optional<uint64_t> Translator::ripAddress(const Step &s, unsigned first) const {
            const auto base = s.inst.getOperand(first).getReg();

            if (!base || StringRef(regs.getName(base)) != "RIP") {
                return {};
            }

            const auto displacement = s.inst.getOperand(first + 3).getImm();
            const auto signedOffset = llvm::SignExtend64<32>(static_cast<uint64_t>(displacement));
            return imageMemory.guestBase() + s.next + static_cast<uint64_t>(signedOffset);
        }

        AddressOperand Translator::decodeAddress(const Step &s, unsigned first, bool access) const {
            const auto &inst = s.inst;
            const auto &base = inst.getOperand(first);
            const auto scale = inst.getOperand(first + 1).getImm();
            const auto &index = inst.getOperand(first + 2);
            const auto displacement = inst.getOperand(first + 3).getImm();
            const auto segment = inst.getOperand(first + 4).getReg();
            const bool hasIndex =
                index.getReg() && StringRef(regs.getName(index.getReg())) != "RIZ";

            if (segment || (scale != 1 && scale != 2 && scale != 4 && scale != 8)) {
                s.reject(FailureCode::UnsupportedInstruction,
                         "unsupported segment or address scale");
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

        Value *Translator::effectiveAddress(const Step &s, unsigned first, bool access) {
            const auto operand = decodeAddress(s, first, access);
            Value *address = ir.getInt64(operand.displacement);
            if (operand.base) {
                address = ir.CreateAdd(address, read(s, *operand.base));
            }

            if (operand.index) {
                auto *term = ir.CreateMul(read(s, *operand.index), ir.getInt64(operand.scale));
                address = ir.CreateAdd(address, term);
            }

            return address;
        }

        RegisterView Translator::destination(const Step &s,
                                             const x86::IntegerInstruction &instruction) const {
            if (instruction.form == x86::Form::Accumulator) {
                return {0, instruction.width};
            }

            return reg(s, s.inst.getOperand(0), instruction.width);
        }

        std::optional<RegisterView> Translator::resultRegister(const Step &s) const {
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

        void Translator::recordWrite(BlockState &state, RegisterView view) {
            state.writes[view.index] |= view.writeMask();
            modified.set(view.index);
            tracksOrigins |= nonvolatile(view.index);
        }

        bool memoryDestination(x86::Form form) {
            return form == x86::Form::MemoryImmediate || form == x86::Form::MemoryRegister ||
                   form == x86::Form::MemoryUnary || form == x86::Form::Store;
        }

        unsigned memoryOperand(const Step &s, const x86::IntegerInstruction &instruction) {
            // In register-destination arithmetic, the output and tied input precede the tuple.
            return memoryDestination(instruction.form) ? 0 : s.inst.getNumOperands() - 5;
        }

        bool hasMemoryOperand(x86::Form form) {
            return memoryDestination(form) || form == x86::Form::Load;
        }

        bool writesRegister(const x86::IntegerInstruction &op) {
            return !memoryDestination(op.form) && op.op != x86::Op::Cmp && op.op != x86::Op::Test;
        }

        void Translator::requireMemory(const Step &s) {
            if (!accessesMemory) {
                imageMemory.checkStackMapping(s);
                accessesMemory = true;
            }
        }

        AddressFact addressFact(const AddressOperand &operand, const AddressFacts &facts) {
            AddressFact result{AddressFact::Constant, operand.displacement};
            if (operand.base) {
                result = result.plus(facts[operand.base->index]);
            }

            if (operand.index) {
                auto term = facts[operand.index->index];
                if (operand.scale != 1 && term.kind != AddressFact::Constant) {
                    return {};
                }

                term.offset *= operand.scale;
                result = result.plus(term);
            }

            return result;
        }

        AddressFact Translator::integerFact(const Step &s, const x86::IntegerInstruction &op,
                                            RegisterView dest, const AddressFacts &facts) const {
            using x86::Form;
            using x86::Op;
            const auto &last = s.inst.getOperand(s.inst.getNumOperands() - 1);
            if (op.op == Op::Mov && op.form == Form::Immediate && dest.width >= 32) {
                return {AddressFact::Constant, static_cast<uint64_t>(last.getImm()) & dest.mask()};
            }

            if (dest.width != 64 || (op.form != Form::Pair && op.form != Form::Immediate &&
                                     op.form != Form::Accumulator)) {
                return {};
            }

            auto rhs = last.isImm() ? AddressFact{AddressFact::Constant,
                                                  static_cast<uint64_t>(last.getImm())}
                                    : facts[reg(s, last, 64).index];
            if (op.op == Op::Mov) {
                return rhs;
            }

            if (op.op == Op::Sub && rhs.kind == AddressFact::Constant) {
                rhs.offset = 0 - rhs.offset;
            } else if (op.op != Op::Add) {
                return {};
            }

            return facts[dest.index].plus(rhs);
        }

        void Translator::planMemoryAccess(const Step &s, const x86::IntegerInstruction &op,
                                          const AddressFacts &facts) {
            const auto operand = decodeAddress(s, memoryOperand(s, op), true);
            const auto fact = addressFact(operand, facts);
            if (fact.kind == AddressFact::Stack) {
                stackAccesses.insert(s.rva);
                return;
            }

            const bool write = memoryDestination(op.form) && op.op != x86::Op::Cmp;
            if (!operand.base && !operand.index) {
                imageMemory.fixedAccess(s, operand.displacement, op.sourceWidth, write);
            } else {
                auto va =
                    fact.kind == AddressFact::Constant ? std::optional(fact.offset) : std::nullopt;
                imageMemory.computedAccess(s, va, op.sourceWidth, write);
            }
        }

        void Translator::traceStackInstruction(const Step &s, StackOp op,
                                               AddressFacts &facts) const {
            auto &rsp = facts[rspIndex];
            if (op == StackOp::Leave) {
                rsp = facts[framePointer.index].plus({AddressFact::Constant, 8});
                facts[framePointer.index] = {};
            } else if (op == StackOp::Pop) {
                rsp = rsp.plus({AddressFact::Constant, 8});
                facts[reg(s, s.inst.getOperand(0), 64).index] = {};
            } else {
                rsp = rsp.plus({AddressFact::Constant, uint64_t(0) - 8});
            }
        }

        void Translator::traceAddresses(const x86::GuestBlock &block, AddressFacts &facts,
                                        bool collect) try {
            for (const auto &s : block.steps) {
                if (auto stack = stackInstruction(s.opcode)) {
                    traceStackInstruction(s, *stack, facts);
                    continue;
                }

                if (auto op = x86::integerInstruction(s.opcode)) {
                    if (collect && hasMemoryOperand(op->form)) {
                        planMemoryAccess(s, *op, facts);
                    }

                    if (writesRegister(*op)) {
                        auto dest = destination(s, *op);
                        facts[dest.index] = integerFact(s, *op, dest, facts);
                    }
                } else if (auto dest = resultRegister(s)) {
                    facts[dest->index] = s.opcode == "LEA64r"
                                             ? addressFact(decodeAddress(s, 1, false), facts)
                                             : AddressFact{};
                }
            }
        } catch (InspectionError &failure) {
            if (failureKind(failure.kind).stage == "lifting") {
                failure.context.blockRva = block.steps.front().rva;
            }

            throw;
        }

        void Translator::proveAvailability(const x86::ControlFlowGraph &graph,
                                           BlockStates &states) {
            auto &entry = states.begin()->second;
            entry.reached = entry.queued = true;
            entry.incoming.registers[rspIndex] = UINT64_MAX;
            entry.incoming.addresses[rspIndex] = {AddressFact::Stack, 0};

            if (mode == EntryMode::RegisterState) {
                std::fill_n(entry.incoming.registers.begin(), callerSlots, UINT64_MAX);
            } else {
                entry.incoming.registers[1] = entry.incoming.registers[2] = UINT64_MAX;
            }

            // The first edge seeds the successor. Later edges (including entry
            // backedges) can only remove facts that no longer agree.
            std::deque<uint32_t> pending{states.begin()->first};
            while (!pending.empty()) {
                auto addr = pending.front();
                pending.pop_front();
                auto &source = states.at(addr);
                source.queued = false;
                auto out = source.transfer();
                if (accessesMemory) {
                    traceAddresses(graph.at(addr), out.addresses, false);
                }

                for (auto target : graph.at(addr).successors) {
                    auto &dest = states.at(target);
                    if (!dest.reached) {
                        dest.incoming = out;
                        dest.reached = true;
                    } else if (!dest.incoming.intersect(out)) {
                        continue;
                    }

                    if (!dest.queued) {
                        dest.queued = true;
                        pending.push_back(target);
                    }
                }
            }
        }

        void Translator::summarize(const Step &s, BlockState &state) {
            if (auto op = stackInstruction(s.opcode)) {
                requireMemory(s);
                tracksOrigins = true;
                recordWrite(state, stackPointer);

                if (*op == StackOp::Leave) {
                    recordWrite(state, framePointer);
                } else if (*op == StackOp::Pop) {
                    recordWrite(state, reg(s, s.inst.getOperand(0), 64));
                }

                return;
            }

            if (s.opcode == "LEA64r" || s.opcode == "LEA64_32r") {
                if (auto address = ripAddress(s, 1)) {
                    imageMemory.addressTaken(s, *address);
                }
            }

            RegisterView dest{};
            if (auto instruction = x86::integerInstruction(s.opcode)) {
                if (instruction->op == x86::Op::Mov && (instruction->form == x86::Form::Pair ||
                                                        instruction->form == x86::Form::Store)) {
                    const auto &src = s.inst.getOperand(s.inst.getNumOperands() - 1);
                    tracksOrigins |=
                        src.isReg() && nonvolatile(reg(s, src, instruction->width).index);
                }

                if (hasMemoryOperand(instruction->form)) {
                    requireMemory(s);
                }

                if (instruction->form == x86::Form::Store) {
                    return;
                }

                auto effect = x86::flagEffect(instruction->op, instruction->width,
                                              shiftCount(s, instruction->form));
                state.flags.generated = effect.apply(state.flags.generated);
                state.flags.carried &= effect.carried;

                if (!writesRegister(*instruction)) {
                    return;
                }

                dest = destination(s, *instruction);
            } else if (auto result = resultRegister(s)) {
                dest = *result;
            } else {
                return;
            }

            recordWrite(state, dest);
        }

        void Translator::move(const Step &s, const x86::IntegerInstruction &instruction) {
            using x86::Form;
            auto [op, form, width, sourceWidth] = instruction;
            const auto &last = s.inst.getOperand(s.inst.getNumOperands() - 1);

            if (form == Form::Store) {
                auto *address = effectiveAddress(s, 0, true);
                auto source = last.isReg() ? readSaved(s, reg(s, last, width), true)
                                           : StoredValue{value(s, last, width)};
                memory.store(address, source, stackAccesses.contains(s.rva));
                return;
            }

            auto dest = destination(s, instruction);

            if (op == x86::Op::Mov && tracksOrigins && (form == Form::Load || form == Form::Pair)) {
                // Copies can carry an opaque save. Address and arithmetic consumers
                // use read(), which requires concrete bytes.
                auto source = form == Form::Load
                                  ? memory.loadSaved(effectiveAddress(s, 1, true), width,
                                                     stackAccesses.contains(s.rva))
                                  : readSaved(s, reg(s, last, width), true);
                writeSaved(dest, source);
                return;
            }

            auto *source = form == Form::Load
                               ? memory.load(effectiveAddress(s, 1, true), sourceWidth,
                                             stackAccesses.contains(s.rva))
                               : value(s, last, sourceWidth);
            write(dest, ir.CreateIntCast(source, ir.getIntNTy(width), op == x86::Op::Movsx));
        }

        void Translator::memoryArithmetic(const Step &s,
                                          const x86::IntegerInstruction &instruction) {
            auto *address = effectiveAddress(s, 0, true);
            const bool stackOnly = stackAccesses.contains(s.rva);
            Value *rhs = nullptr;
            if (instruction.form != x86::Form::MemoryUnary) {
                rhs = value(s, s.inst.getOperand(s.inst.getNumOperands() - 1), instruction.width);
            }

            if (instruction.op == x86::Op::Cmp) {
                auto *lhs = memory.load(address, instruction.width, stackOnly);
                semantics.arithmetic(instruction.op, lhs, rhs);
                return;
            }

            memory.modify(address, instruction.width, stackOnly, [&](Value *lhs) {
                return semantics.arithmetic(instruction.op, lhs, rhs);
            });
        }

        void Translator::integer(const Step &s, const x86::IntegerInstruction &instruction) {
            using x86::Form;
            using x86::Op;
            const auto op = instruction.op;
            const auto form = instruction.form;
            const auto width = instruction.width;

            if (op == Op::Mov || op == Op::Movsx || op == Op::Movzx) {
                move(s, instruction);
                return;
            }

            if (memoryDestination(form)) {
                memoryArithmetic(s, instruction);
                return;
            }

            const auto &i = s.inst;
            const auto &last = i.getOperand(i.getNumOperands() - 1);
            auto dest = destination(s, instruction);

            if (form == Form::ShiftCL || form == Form::ShiftOne || form == Form::ShiftImmediate) {
                auto fixed = shiftCount(s, form);
                auto *count = fixed ? ir.getInt8(*fixed) : read(s, {1, 8});
                write(dest, semantics.shift(op, read(s, dest), count));

                return;
            }

            // Equal operands cancel even if the guest register has no incoming value.
            // SBB still subtracts CF, and CMP only updates flags.
            bool cancel = (op == Op::Xor || op == Op::Sub || op == Op::Cmp || op == Op::Sbb) &&
                          form == Form::Pair && i.getOperand(0).getReg() == last.getReg();
            Value *lhs = cancel ? ir.getIntN(width, 0) : read(s, dest);
            Value *rhs = nullptr;

            if (form == Form::Load) {
                rhs = memory.load(effectiveAddress(s, memoryOperand(s, instruction), true), width,
                                  stackAccesses.contains(s.rva));
            } else if (form != Form::Reg) {
                rhs = cancel ? lhs : value(s, last, width);
            }

            if (op == Op::Adc || op == Op::Sbb) {
                require(s, x86::CF);
            }

            auto *result = semantics.arithmetic(op, lhs, rhs);
            if (op != Op::Cmp && op != Op::Test) {
                write(dest, result);
            }
        }

        void Translator::lowerStack(const Step &s, StackOp op) {
            if (op == StackOp::PushRegister || op == StackOp::PushImmediate) {
                const auto &operand = s.inst.getOperand(0);
                auto source = op == StackOp::PushRegister ? readSaved(s, reg(s, operand, 64), true)
                                                          : StoredValue{value(s, operand, 64)};
                auto *next = ir.CreateSub(read(s, stackPointer), ir.getInt64(8));
                write(stackPointer, next);
                memory.store(next, source, true);
                return;
            }

            if (op == StackOp::Leave) {
                write(stackPointer, read(s, framePointer));
            }

            auto *address = read(s, stackPointer);
            auto saved = memory.loadSaved(address, 64, true);
            write(stackPointer, ir.CreateAdd(address, ir.getInt64(8)));
            auto destination =
                op == StackOp::Leave ? framePointer : reg(s, s.inst.getOperand(0), 64);
            writeSaved(destination, saved);
        }

        void Translator::lower(const Step &s) {
            if (auto op = stackInstruction(s.opcode)) {
                lowerStack(s, *op);
                return;
            }

            if (s.opcode == "NOOPW" || s.opcode == "NOOPL") {
                return;
            }

            if (auto instruction = x86::integerInstruction(s.opcode)) {
                integer(s, *instruction);
                return;
            }

            auto result = resultRegister(s);
            if (!result) {
                s.reject(FailureCode::UnsupportedInstruction,
                         "unsupported instruction or operand form");
            }

            const auto dest = *result;
            if (s.opcode == "CWDE" || s.opcode == "CDQE") {
                auto *source = read(s, {0, dest.width / 2});
                write(dest, ir.CreateSExt(source, ir.getIntNTy(dest.width)));
            } else if (s.opcode == "LEA64r" || s.opcode == "LEA64_32r") {
                write(dest, ir.CreateTruncOrBitCast(effectiveAddress(s, 1, false),
                                                    ir.getIntNTy(dest.width)));
            } else if (s.opcode == "SETCCr") {
                write(dest, ir.CreateZExt(condition(s), ir.getInt8Ty()));
            } else if (s.opcode == "CMOV16rr" || s.opcode == "CMOV32rr" || s.opcode == "CMOV64rr") {
                auto *old = read(s, dest);
                auto *src = value(s, s.inst.getOperand(2), dest.width);

                write(dest, ir.CreateSelect(condition(s), src, old));
            } else if (s.opcode == "LAHF") {
                Value *byte = ir.getInt8(2);

                for (auto [flag, bit] : {std::pair{x86::SF, 7U},
                                         {x86::ZF, 6U},
                                         {x86::AF, 4U},
                                         {x86::PF, 2U},
                                         {x86::CF, 0U}}) {
                    byte = ir.CreateOr(
                        byte, ir.CreateShl(ir.CreateZExt(require(s, flag), ir.getInt8Ty()), bit));
                }

                write(dest, byte);
            } else {
                llvm_unreachable("unhandled result-register instruction");
            }
        }

        void Translator::checkReturnRegisters(const Step &s) {
            if (mode == EntryMode::RegisterState) {
                // Every exposed slot is defined on entry and crosses this boundary.
                for (unsigned i = 0; i < callerSlots; ++i) {
                    read(s, {i, 64});
                }

                return;
            }

            read(s, {0, 64});

            for (unsigned i = framePointer.index; i < std::size(registerNames); ++i) {
                if (modified[i]) {
                    auto saved = readSaved(s, {i, 64}, true);
                    auto *sameBits = ir.CreateICmpEQ(saved.bits, entryValues[i]);
                    auto *sameOrigin = ir.CreateICmpEQ(saved.marks, ir.getInt64(entryMarks(i)));
                    memory.guard(ir.CreateAnd(sameBits, sameOrigin));
                }
            }
        }

        void Translator::emitReturn(const Step &s) {
            if (mode == EntryMode::WindowsX64I64Pair && defined[0] != UINT64_MAX) {
                s.reject(FailureCode::UndefinedRegister, "return with undefined RAX");
            }

            if (modified[rspIndex] || accessesMemory) {
                memory.checkReturn(read(s, stackPointer));
            }

            if (tracksOrigins) {
                checkReturnRegisters(s);
            }

            ir.CreateRetVoid();
        }

        void Translator::emitBlock(const x86::GuestBlock &block, const BlockStates &states) {
            const auto &last = block.steps.back();
            auto body = ArrayRef(block.steps);
            if (block.exit != x86::Flow::Fallthrough && block.exit != x86::Flow::FallOff) {
                body = body.drop_back();
            }

            for (const auto &s : body) {
                lower(s);
            }

            switch (block.exit) {
            case x86::Flow::Return:
                emitReturn(last);
                break;
            case x86::Flow::Conditional:
                ir.CreateCondBr(condition(last), states.at(block.successors[0]).irBlock,
                                states.at(block.successors[1]).irBlock);
                break;
            case x86::Flow::Fallthrough:
            case x86::Flow::Jump:
                ir.CreateBr(states.at(block.successors.front()).irBlock);
                break;
            case x86::Flow::FallOff:
                last.reject(FailureCode::UnsupportedControlFlow,
                            "fallthrough outside function to " + hex(last.next), last.next);
            }
        }

        void connectFlags(const x86::ControlFlowGraph &graph, const BlockStates &states) {
            for (const auto &[addr, block] : graph) {
                const auto &source = states.at(addr);
                for (auto dest : block.successors) {
                    const auto &phis = states.at(dest).phis;
                    for (unsigned f = 0; f < x86::FlagCount; ++f) {
                        if (phis[f]) {
                            assert(source.outgoing[f] &&
                                   "availability disagrees with flag lowering");
                            phis[f]->addIncoming(source.outgoing[f], source.exitBlock);
                        }
                    }
                }
            }
        }

        void Translator::initializeRegisters() {
            auto *locals = ArrayType::get(ir.getInt64Ty(), std::size(registerNames) - callerSlots);
            localRegisters = ir.CreateAlloca(locals, nullptr, "local.registers");
            ir.CreateStore(ConstantAggregateZero::get(locals), localRegisters);
            ir.CreateAlignedStore(ir.getInt64(x86::GuestMemory::entryRsp),
                                  slot(impl->getArg(0), rspIndex), registerStateAlignment);

            if (!tracksOrigins) {
                return;
            }

            registerMarks = ir.CreateAlloca(ir.getInt64Ty(), ir.getInt32(std::size(registerNames)),
                                            "register.marks");

            for (unsigned i = 0; i < std::size(registerNames); ++i) {
                ir.CreateAlignedStore(ir.getInt64(entryMarks(i)), markSlot(i),
                                      registerStateAlignment);

                if (nonvolatile(i)) {
                    // Capture a stable, unspecified entry value. Identity bytes
                    // distinguish independent origins even if freeze chooses equal bits.
                    entryValues[i] = ir.CreateFreeze(PoisonValue::get(ir.getInt64Ty()), "incoming");
                    ir.CreateAlignedStore(entryValues[i], slot(impl->getArg(0), i),
                                          registerStateAlignment);
                }
            }
        }

        void Translator::translate(const x86::ControlFlowGraph &graph) {
            BlockStates states;
            auto *entry = BasicBlock::Create(ir.getContext(), "entry", impl);
            for (const auto &[addr, block] : graph) {
                auto &state = states[addr];
                state.irBlock =
                    BasicBlock::Create(ir.getContext(), "rva_" + utohexstr(addr, true), impl);
                try {
                    for (const auto &s : block.steps) {
                        summarize(s, state);
                    }
                } catch (InspectionError &failure) {
                    if (failureKind(failure.kind).stage == "lifting") {
                        failure.context.blockRva = addr;
                    }

                    throw;
                }
            }

            proveAvailability(graph, states);
            ir.SetInsertPoint(entry);
            initializeRegisters();

            if (accessesMemory) {
                for (const auto &[addr, block] : graph) {
                    auto facts = states.at(addr).incoming.addresses;
                    traceAddresses(block, facts, true);
                }

                memory.allocate(imageMemory.emitResolver(*impl->getParent(), ir));
            }

            ir.CreateBr(states.begin()->second.irBlock);
            for (const auto &[addr, block] : graph) {
                auto &state = states.at(addr);
                ir.SetInsertPoint(state.irBlock);
                defined = state.incoming.registers;
                semantics.flags = {};
                for (unsigned f = 0; f < x86::FlagCount; ++f) {
                    if (state.incoming.flags[f]) {
                        state.phis[f] = ir.CreatePHI(ir.getInt1Ty(), 0, x86::flagNames[f]);
                        semantics.flags[f] = state.phis[f];
                    }
                }

                try {
                    emitBlock(block, states);
                } catch (InspectionError &failure) {
                    if (failureKind(failure.kind).stage == "lifting") {
                        failure.context.blockRva = addr;
                    }

                    throw;
                }

                state.exitBlock = ir.GetInsertBlock();
                state.outgoing = semantics.flags;
            }

            connectFlags(graph, states);
        }

        struct ValidatedEntry {
            LiftRequest request;
            uint64_t guestBase;
            // The analyzed image owns both the section and its bytes through generation.
            MappedRange code;
        };

        ValidatedEntry validateEntry(const AnalyzedImage &analysis, LiftRequest request,
                                     FailureContext &location) {
            const auto rva = request.startRva;
            const auto &module = analysis.module();

            if (module.dll) {
                throw atRva(FailureCode::DllLift, rva, "DLL lifting is unsupported");
            }

            const auto &functions = analysis.functions();
            auto it = llvm::lower_bound(functions, rva, [](const auto &function, uint32_t address) {
                return function.record.begin < address;
            });

            const auto first = it;
            // An invalid empty record can share its start with a valid, disjoint record.
            while (it != functions.end() && it->record.begin == rva &&
                   (it->defect || it->overlapGroup)) {
                ++it;
            }

            if (it == functions.end() || it->record.begin != rva) {
                auto kind = FailureCode::InvalidEntry;

                if (it - first == 1 && !first->overlapGroup &&
                    first->defect == RecordDefect::UnmappedCode) {
                    kind = FailureCode::UnmappedCode;
                    location.endRva = first->record.end;
                }

                throw atRva(kind, rva,
                            "expected an exact, valid, unambiguous discovered function start");
            }

            const auto end = it->record.end;
            location.endRva = end;

            if (const auto version = it->unsupportedUnwindVersion) {
                throw atRva(FailureCode::UnsupportedUnwind, rva,
                            "unsupported unwind version " + Twine(*version));
            }

            if (it->chainedFragment) {
                throw atRva(FailureCode::ChainedEntry, rva,
                            "chained unwind fragment has no independent function entry");
            }

            auto code = analysis.image().mapRva(rva, end - rva);

            if (!code) {
                throw atRva(FailureCode::UnmappedCode, rva,
                            "function bytes outside file-backed sections");
            }

            location.fileOffset = code->fileOffset;

            for (const auto &block : module.relocations) {
                for (const auto &rel : block.entries) {
                    const auto width = relocationWidth(rel.type);

                    if (width && rel.rva < end && uint64_t(rel.rva) + width > rva) {
                        throw atRva(FailureCode::RelocationOverlap, rva,
                                    "function bytes overlap base relocation at " + hex(rel.rva));
                    }
                }
            }

            const uint64_t guestBase = request.guestLoadBase.value_or(module.imageBase);
            if (module.relocationsStripped && guestBase != module.imageBase) {
                throw atRva(FailureCode::ImageMemory, rva,
                            "base relocations are stripped: selected guest base " + hex(guestBase) +
                                " differs from preferred image base " + hex(module.imageBase));
            }

            for (const auto &section : module.sections) {
                const uint64_t endRva = uint64_t(section.rva) + section.virtualSize;
                if (section.virtualSize && endRva - 1 > UINT64_MAX - guestBase) {
                    throw atRva(FailureCode::ImageMemory, rva,
                                "selected guest load base overflows section " + section.name);
                }
            }

            return {request, guestBase, *code};
        }

        std::unique_ptr<llvm::Module> generateAmd64IR(const ValidatedEntry &entry,
                                                      const ParsedImage &image,
                                                      LLVMContext &context) {
            const uint32_t rva = entry.request.startRva;
            // LLVM registry writes must finish before another lift looks up its decoder.
            static std::once_flag registerAmd64;
            std::call_once(registerAmd64, [] {
                LLVMInitializeX86TargetInfo();
                LLVMInitializeX86TargetMC();
                LLVMInitializeX86Disassembler();
            });

            const Triple guestTriple("x86_64-pc-windows-msvc");
            std::string error;
            const auto *target = TargetRegistry::lookupTarget(guestTriple, error);

            if (!target) {
                throw atRva(FailureCode::BackendSetup, rva, error);
            }

            std::unique_ptr<MCRegisterInfo> regs(target->createMCRegInfo(guestTriple));
            std::unique_ptr<MCInstrInfo> instructions(target->createMCInstrInfo());
            std::unique_ptr<MCSubtargetInfo> sub(
                target->createMCSubtargetInfo(guestTriple, "generic", ""));

            if (!regs || !instructions || !sub) {
                throw atRva(FailureCode::BackendSetup, rva, "AMD64 decoder metadata unavailable");
            }

            const MCTargetOptions options;
            auto assembly = x86::createAsmInfo(*target, *regs, guestTriple, options);

            if (!assembly) {
                throw atRva(FailureCode::BackendSetup, rva,
                            "AMD64 assembly information unavailable");
            }

            MCContext mc(guestTriple, *assembly, *regs, *sub);
            std::unique_ptr<MCDisassembler> dis(target->createMCDisassembler(*sub, mc));

            if (!dis) {
                throw atRva(FailureCode::BackendSetup, rva, "AMD64 disassembler unavailable");
            }

            const auto graph = x86::discoverCFG(entry.code.bytes, rva, *dis, *instructions);
            auto module = std::make_unique<llvm::Module>("forge_" + utohexstr(rva, true), context);
            const Triple outputTriple("arm64-apple-macosx11.0.0");
            module->setTargetTriple(outputTriple);
            module->setDataLayout(outputTriple.computeDataLayout());
            x86::ImageMemory imageMemory(image, entry.guestBase);
            Translator(*module, rva, entry.request.mode, *regs, imageMemory).translate(graph);
            return module;
        }
    } // namespace

    void verifyLiftedIR(const llvm::Module &module, const fs::path &input, uint32_t entryRva) {
        std::string message;
        llvm::raw_string_ostream reason(message);

        if (llvm::verifyModule(module, &reason)) {
            auto failure =
                atRva(FailureCode::VerificationFailed, entryRva, "LLVM verifier: " + message);
            failure.context.input = input;
            failure.context.entryRva = entryRva;
            throw failure;
        }
    }

    std::unique_ptr<llvm::Module> generateIR(const AnalyzedImage &analysis, LiftRequest request,
                                             llvm::LLVMContext &context) {
        FailureContext location;
        location.input = analysis.module().path;
        location.entryRva = request.startRva;
        FailureCode internal = FailureCode::EntryInternal;

        try {
            const auto entry = validateEntry(analysis, request, location);
            internal = FailureCode::LiftingInternal;
            auto module = generateAmd64IR(entry, analysis.image(), context);
            internal = FailureCode::VerificationInternal;
            verifyLiftedIR(*module, location.input, request.startRva);
            return module;
        } catch (InspectionError &failure) {
            if (location.fileOffset && failure.context.instructionRva) {
                *location.fileOffset += *failure.context.instructionRva - request.startRva;
            }

            failure.context.input = std::move(location.input);
            failure.context.entryRva = location.entryRva;
            if (failureKind(failure.kind).stage == "pe") {
                throw;
            }

            failure.context.endRva = location.endRva;
            if (!failure.context.fileOffset) {
                failure.context.fileOffset = location.fileOffset;
            }

            throw;
        } catch (const std::exception &error) {
            InspectionError failure(error.what(), internal);
            failure.context = std::move(location);
            throw failure;
        }
    }
} // namespace forge
