#include "lift/lift.h"

#include "analysis/analysis.h"
#include "lift/execution_context.h"
#include "lift/group_analysis.h"
#include "lift/operands.h"
#include "lift/recovery.h"

#include "llvm/IR/CFG.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

#include <set>

namespace forge {
    namespace {
        using namespace llvm;
        using x86::framePointer;
        using x86::nonvolatile;
        using x86::RegisterView;
        using x86::StackOp;
        using x86::stackPointer;
        using x86::Step;
        using x86::StoredValue;

        // The signatureless ABI accepts a four-byte-aligned register array.
        constexpr auto registerStateAlignment = Align::Constant<4>();

        struct BlockState {
            BasicBlock *irBlock = nullptr;
            BasicBlock *exitBlock = nullptr;
            std::array<PHINode *, x86::FlagCount> phis{};
            x86::Flags outgoing{};
        };

        using BlockStates = std::map<uint32_t, BlockState>;
        using GuestBodies = std::map<uint32_t, Function *>;

        class Translator {
          public:
            Translator(uint32_t rva, const x86::RecoveredFunction &function,
                       const x86::GroupAnalysis &analysis, const GuestBodies &bodies,
                       const x86::InstructionOperands &operands)
                : impl(bodies.at(rva)), ir(impl->getContext()), semantics(ir), memory(ir),
                  function(function), analysis(analysis), bodies(bodies),
                  plan(analysis.functions.at(rva)), operands(operands),
                  flow(analysis.flows.at(rva)) {}

            void translate(const x86::ContextLayout &layout, Function *resolver, bool typedRoot);

          private:
            Function *impl;
            IRBuilder<> ir;
            x86::IntegerSemantics semantics;
            x86::GuestMemory memory;
            const x86::RecoveredFunction &function;
            const x86::GroupAnalysis &analysis;
            const GuestBodies &bodies;
            const x86::FunctionPlan &plan;
            const x86::InstructionOperands &operands;
            const x86::FunctionFlow &flow;
            bool tracksOrigins = false;
            bool requiresFullReturn = false;
            x86::ContextView context;
            Value *entryRsp = nullptr;
            x86::Defined defined{};
            x86::FlagSet provedFlags;

            Value *slot(unsigned index) {
                return ir.CreateInBoundsGEP(ir.getInt64Ty(), context.registers, ir.getInt32(index));
            }

            Value *flagSlot(unsigned index) {
                return ir.CreateInBoundsGEP(ir.getInt1Ty(), context.flags, ir.getInt32(index));
            }

            void storeFlags();
            void lowerCall(const Step &s, const x86::ResolvedCallSite &call);
            void emitReturn(const Step &s);
            void emitDispatch(const x86::GuestBlock &block, const BlockStates &states);
            void lowerStack(const Step &s, StackOp op);
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
            Value *effectiveAddress(const Step &s, unsigned first, bool access);
            void emitBlock(const x86::GuestBlock &block, const BlockStates &states);
        };

        Value *Translator::markSlot(unsigned index) {
            return ir.CreateInBoundsGEP(ir.getInt64Ty(), context.marks, ir.getInt32(index));
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
                         "read of undefined incoming " + x86::registerName(view.index));
            }

            return {loadView(slot(view.index), view),
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

            return read(s, operands.reg(s, op, width));
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
            storeView(slot(view.index), view, value.bits, 0);

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
            if (!provedFlags[flag] || !semantics.flags[flag]) {
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

        Value *Translator::effectiveAddress(const Step &s, unsigned first, bool access) {
            const auto operand = operands.decodeAddress(s, first, access);
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

        void Translator::move(const Step &s, const x86::IntegerInstruction &instruction) {
            using x86::Form;
            auto [op, form, width, sourceWidth] = instruction;
            const auto &last = s.inst.getOperand(s.inst.getNumOperands() - 1);

            if (form == Form::Store) {
                auto *address = effectiveAddress(s, 0, true);
                auto source = last.isReg() ? readSaved(s, operands.reg(s, last, width), true)
                                           : StoredValue{value(s, last, width)};
                memory.store(address, source, plan.stackAccesses.contains(s.rva));
                return;
            }

            auto dest = operands.destination(s, instruction);

            if (op == x86::Op::Mov && tracksOrigins && (form == Form::Load || form == Form::Pair)) {
                // Copies can carry an opaque save. Address and arithmetic consumers
                // use read(), which requires concrete bytes.
                auto source = form == Form::Load
                                  ? memory.loadSaved(effectiveAddress(s, 1, true), width,
                                                     plan.stackAccesses.contains(s.rva))
                                  : readSaved(s, operands.reg(s, last, width), true);
                writeSaved(dest, source);
                return;
            }

            auto *source = form == Form::Load
                               ? memory.load(effectiveAddress(s, 1, true), sourceWidth,
                                             plan.stackAccesses.contains(s.rva))
                               : value(s, last, sourceWidth);
            write(dest, ir.CreateIntCast(source, ir.getIntNTy(width), op == x86::Op::Movsx));
        }

        void Translator::memoryArithmetic(const Step &s,
                                          const x86::IntegerInstruction &instruction) {
            auto *address = effectiveAddress(s, 0, true);
            const bool stackOnly = plan.stackAccesses.contains(s.rva);
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
            auto dest = operands.destination(s, instruction);

            if (form == Form::ShiftCL || form == Form::ShiftOne || form == Form::ShiftImmediate) {
                auto fixed = shiftCount(s, form);
                auto *count = fixed ? ir.getInt8(*fixed) : read(s, {1, 8});
                write(dest, semantics.shift(op, read(s, dest), count));

                return;
            }

            // Equal operands cancel even if the guest register has no incoming value.
            // SBB still subtracts CF, and CMP only updates flags.
            const bool cancel = operandsCancel(s, instruction);
            Value *lhs = cancel ? ir.getIntN(width, 0) : read(s, dest);
            Value *rhs = nullptr;

            if (form == Form::Load) {
                rhs = memory.load(effectiveAddress(s, memoryOperand(s, instruction), true), width,
                                  plan.stackAccesses.contains(s.rva));
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
                auto source = op == StackOp::PushRegister
                                  ? readSaved(s, operands.reg(s, operand, 64), true)
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
                op == StackOp::Leave ? framePointer : operands.reg(s, s.inst.getOperand(0), 64);
            writeSaved(destination, saved);
        }

        void Translator::lower(const Step &s) {
            if (auto op = x86::stackInstruction(s.opcode)) {
                lowerStack(s, *op);
                return;
            }

            if (x86::isNoop(s)) {
                return;
            }

            if (auto instruction = x86::integerInstruction(s.opcode)) {
                integer(s, *instruction);
                return;
            }

            auto result = operands.resultRegister(s);
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

        void Translator::storeFlags() {
            for (unsigned f = 0; f < x86::FlagCount; ++f) {
                if (semantics.flags[f]) {
                    ir.CreateStore(semantics.flags[f], flagSlot(f));
                }
            }
        }

        void Translator::lowerCall(const Step &s, const x86::ResolvedCallSite &call) {
            const auto guestBase = analysis.image.guestBase();
            if (call.kind == x86::CallKind::RipRelativeRegister) {
                auto *target = value(s, s.inst.getOperand(0), 64);
                memory.guard(ir.CreateICmpEQ(target, ir.getInt64(guestBase + call.callee)));
            }

            const uint64_t nextVA = guestBase + call.continuation;
            auto *calleeRsp = memory.pushReturn(read(s, stackPointer), entryRsp, nextVA);
            write(stackPointer, calleeRsp);
            const auto &callee = analysis.functions.at(call.callee);
            const auto saved = x86::captureNonvolatiles(ir, context, callee.modified);
            storeFlags();
            ir.CreateCall(bodies.at(call.callee), impl->getArg(0));

            // This continuation is the other half of the guest RET. No caller
            // instruction executes until its own activation validates the frame.
            write(stackPointer, memory.popReturn(read(s, stackPointer), calleeRsp, nextVA));
            x86::checkNonvolatiles(ir, memory, context, saved);
            const auto &effect = analysis.flows.at(call.callee).returns;
            const auto out = effect.apply({defined, provedFlags});
            defined = out.registers;
            provedFlags = out.flags;

            for (unsigned f = 0; f < x86::FlagCount; ++f) {
                const bool available =
                    effect.flags.generated[f] || (effect.flags.carried[f] && semantics.flags[f]);
                semantics.flags[f] =
                    available ? ir.CreateLoad(ir.getInt1Ty(), flagSlot(f)) : nullptr;
            }
        }

        void Translator::emitReturn(const Step &s) {
            if (requiresFullReturn && defined[0] != UINT64_MAX) {
                s.reject(FailureCode::UndefinedRegister, "return with undefined RAX");
            }

            if (!function.incoming.empty()) {
                storeFlags();
            }

            ir.CreateRetVoid();
        }

        void Translator::emitDispatch(const x86::GuestBlock &block, const BlockStates &states) {
            const auto &jump = block.steps.back();
            auto *target = value(jump, jump.inst.getOperand(0), 64);
            auto *fault = BasicBlock::Create(ir.getContext(), "dispatch.fault", impl);

            {
                IRBuilderBase::InsertPointGuard restore(ir);
                ir.SetInsertPoint(fault);
                ir.CreateIntrinsic(Intrinsic::trap, {});
                ir.CreateUnreachable();
            }

            auto *dispatch = ir.CreateSwitch(target, fault);
            std::set<uint32_t> seen;

            for (auto dest : block.successors) {
                if (seen.insert(dest).second) {
                    dispatch->addCase(ir.getInt64(analysis.image.guestBase() + dest),
                                      states.at(dest).irBlock);
                }
            }
        }

        void Translator::emitBlock(const x86::GuestBlock &block, const BlockStates &states) {
            const auto &last = block.steps.back();
            auto instructions = ArrayRef(block.steps);
            if (block.exit != x86::Flow::Fallthrough && block.exit != x86::Flow::FallOff) {
                instructions = instructions.drop_back();
            }

            for (const auto &s : instructions) {
                if (const auto *call = function.callAt(s.rva)) {
                    lowerCall(s, *call);
                } else {
                    lower(s);

                    if (auto op = x86::integerInstruction(s.opcode)) {
                        provedFlags = x86::flagEffect(op->op, op->width, shiftCount(s, op->form))
                                          .apply(provedFlags);
                    }
                }
            }

            switch (block.exit) {
            case x86::Flow::Return:
                emitReturn(last);
                break;
            case x86::Flow::Conditional:
                ir.CreateCondBr(condition(last), states.at(block.successors[0]).irBlock,
                                states.at(block.successors[1]).irBlock);
                break;
            case x86::Flow::Indirect:
                emitDispatch(block, states);
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

        void connectEdgeFlags(const BlockState &source, const BlockState &dest) {
            for (unsigned f = 0; f < x86::FlagCount; ++f) {
                if (auto *phi = dest.phis[f]) {
                    assert(source.outgoing[f] && "availability disagrees with flag lowering");
                    phi->addIncoming(source.outgoing[f], source.exitBlock);
                }
            }
        }

        void connectFlags(const BlockStates &states) {
            std::map<const BasicBlock *, const BlockState *> headers;

            for (const auto &[addr, state] : states) {
                headers.emplace(state.irBlock, &state);
            }

            // Conditional branches may have parallel edges. A switch on the computed VA
            // has one edge per distinct VA, plus a trap block with no guest state.
            for (const auto &[addr, source] : states) {
                for (const auto *dest : llvm::successors(source.exitBlock)) {
                    const auto header = headers.find(dest);

                    if (header == headers.end()) {
                        continue;
                    }

                    connectEdgeFlags(source, *header->second);
                }
            }
        }

        void Translator::translate(const x86::ContextLayout &layout, Function *resolver,
                                   bool typedRoot) {
            const auto &graph = function.graph;
            requiresFullReturn = typedRoot;
            tracksOrigins = layout.origins;
            BlockStates states;
            auto *entry = BasicBlock::Create(ir.getContext(), "entry", impl);
            ir.SetInsertPoint(entry);
            context = x86::ContextView(ir, layout, impl->getArg(0));
            memory.bind(context.bytes, context.validity, resolver);
            entryRsp = loadView(slot(x86::rspIndex), stackPointer);

            // A shared helper can preserve an incoming flag for one caller while
            // another enters with it undefined. Track the physical bit separately
            // from the all-callers proof used by require().
            x86::FlagSet physicalEntry;
            x86::Flags incomingFlags{};

            if (!function.incoming.empty()) {
                physicalEntry.set();

                for (unsigned f = 0; f < x86::FlagCount; ++f) {
                    incomingFlags[f] = ir.CreateLoad(ir.getInt1Ty(), flagSlot(f));
                }
            }

            for (const auto &[address, block] : graph) {
                states[address].irBlock =
                    BasicBlock::Create(ir.getContext(), "rva_" + utohexstr(address, true), impl);
            }

            ir.CreateBr(states.at(function.entry).irBlock);

            for (const auto &[address, block] : graph) {
                auto &state = states.at(address);
                const auto &prefix = flow.blocks.at(address).incoming;
                const auto available = prefix.apply(flow.entry);
                defined = available.registers;
                provedFlags = available.flags;
                const auto physical = prefix.flags.apply(physicalEntry);
                ir.SetInsertPoint(state.irBlock);
                semantics.flags = {};

                for (unsigned f = 0; f < x86::FlagCount; ++f) {
                    if (physical[f]) {
                        auto *phi = ir.CreatePHI(ir.getInt1Ty(), 0, x86::flagNames[f]);
                        state.phis[f] = phi;
                        semantics.flags[f] = phi;

                        if (address == function.entry) {
                            phi->addIncoming(incomingFlags[f], entry);
                        }
                    }
                }

                try {
                    emitBlock(block, states);
                } catch (InspectionError &failure) {
                    failure.context.blockRva = address;
                    throw;
                }

                state.exitBlock = ir.GetInsertBlock();
                state.outgoing = semantics.flags;
            }

            connectFlags(states);
        }

        std::unique_ptr<llvm::Module> emitGroup(const x86::RecoveredFunctionGroup &group,
                                                const x86::GroupAnalysis &analysis, EntryMode mode,
                                                LLVMContext &context) {
            const auto root = group.root();
            auto module = std::make_unique<llvm::Module>("forge_" + utohexstr(root, true), context);
            const Triple target("arm64-apple-macosx11.0.0");
            module->setTargetTriple(target);
            module->setDataLayout(target.computeDataLayout());

            GuestBodies bodies;
            auto *type =
                FunctionType::get(Type::getVoidTy(context), PointerType::getUnqual(context), false);

            for (const auto &[rva, function] : group.functions()) {
                auto *body = Function::Create(type, Function::InternalLinkage,
                                              "forge_guest_" + utohexstr(rva, true), *module);
                body->getArg(0)->setName("context");
                bodies.emplace(rva, body);
            }

            const x86::ContextLayout layout(context, analysis.origins, analysis.stack);
            auto *resolver =
                x86::emitEntryAdapter(*bodies.at(root), root, mode, layout, analysis.image,
                                      analysis.functions.at(root).modified);
            const x86::InstructionOperands operands{group.registers(), analysis.image.guestBase()};

            for (const auto &[rva, function] : group.functions()) {
                Translator translator(rva, function, analysis, bodies, operands);
                translator.translate(layout, resolver,
                                     rva == root && mode == EntryMode::WindowsX64I64Pair);
            }

            return module;
        }
    } // namespace

    void verifyLiftedIR(const llvm::Module &module, const fs::path &input, uint32_t entryRva) {
        std::string message;
        llvm::raw_string_ostream reason(message);

        if (llvm::verifyModule(module, &reason)) {
            InspectionError failure(hex(entryRva) + ": LLVM verifier: " + message,
                                    FailureCode::VerificationFailed);
            failure.context.input = input;
            failure.context.entryRva = entryRva;
            throw failure;
        }
    }

    std::unique_ptr<llvm::Module> generateIR(const AnalyzedImage &analysis, LiftRequest request,
                                             llvm::LLVMContext &context) {
        const auto entry = x86::validateEntry(analysis, request.startRva);
        const auto guestBase = x86::validateGuestBase(entry, request.guestLoadBase);
        const x86::RecoveredFunctionGroup group(entry);
        const auto prepared = x86::analyzeGroup(group, guestBase, request.mode);
        auto stage = FailureCode::LiftingInternal;

        try {
            auto module = emitGroup(group, prepared, request.mode, context);
            stage = FailureCode::VerificationInternal;
            verifyLiftedIR(*module, analysis.module().path, group.root());
            return module;
        } catch (InspectionError &failure) {
            group.annotateFailure(failure);
            throw;
        } catch (const std::exception &error) {
            InspectionError failure(error.what(), stage);
            group.annotateFailure(failure);
            throw failure;
        }
    }
} // namespace forge
