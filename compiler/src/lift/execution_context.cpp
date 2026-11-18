#include "lift/execution_context.h"
#include "lift/group_analysis.h"

#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <type_traits>

namespace forge::x86 {
    using namespace llvm;

    static_assert(std::extent_v<decltype(forge_rt_execution::registers)> == registerCount);
    static_assert(std::extent_v<decltype(forge_rt_execution::registerMarks)> == registerCount);
    static_assert(std::extent_v<decltype(forge_rt_execution::flags)> == FlagCount);
    static_assert(offsetof(forge_rt_execution, directionFlag) ==
                  offsetof(forge_rt_execution, flags) + FlagCount);

    ContextLayout::ContextLayout(LLVMContext &context, bool origins, bool stack, bool runtime,
                                 bool process)
        : origins(origins), stack(stack), runtime(runtime), process(process) {
        const auto registers = [&](unsigned count) {
            return ArrayType::get(Type::getInt64Ty(context), count);
        };

        if (process) {
            // Native forge_rt_execution layout. Guest registers and flags live in this
            // process's execution record. Stack and image addresses here are host borrows.
            auto *pointer = PointerType::getUnqual(context);
            auto *word = Type::getInt64Ty(context);
            type = StructType::get(pointer, word, pointer, pointer, pointer, word, word,
                                   processResultType(context), registers(registerCount),
                                   registers(registerCount),
                                   ArrayType::get(Type::getInt8Ty(context), FlagCount + 1));
            return;
        }

        auto *stackType =
            ArrayType::get(Type::getInt8Ty(context), stack ? GuestMemory::capacity : 0);
        // Keep the following byte-backed guest stack naturally aligned for qword atomics.
        auto *flagType = ArrayType::get(Type::getInt1Ty(context), alignTo(FlagCount + 1, 8));
        SmallVector<Type *> fields{registers(registerCount), registers(origins ? registerCount : 0),
                                   flagType, stackType, stackType};
        if (runtime) {
            fields.push_back(PointerType::getUnqual(context));
            fields.push_back(Type::getInt64Ty(context));
        }

        type = StructType::get(context, fields);
    }

    ContextView::ContextView(IRBuilder<> &ir, const ContextLayout &layout, Value *context) {
        const auto field = [&](unsigned index, const char *name) {
            return ir.CreateStructGEP(layout.type, context, index, name);
        };

        if (layout.process) {
            instance = field(0, "runtime.instance");
            thread = field(1, "runtime.thread");
            regions = ir.CreateLoad(ir.getPtrTy(), field(2, "region.table"));
            bytes = ir.CreateLoad(ir.getPtrTy(), field(3, "stack.bytes"));
            validity = ir.CreateLoad(ir.getPtrTy(), field(4, "stack.valid"));
            result = field(7, "process.result");
            registers = field(8, "registers");
            marks = layout.origins ? field(9, "register.marks") : nullptr;
            flags = field(10, "flags");
            directionFlag = ir.CreateInBoundsGEP(ir.getInt8Ty(), flags, ir.getInt32(FlagCount));
            return;
        }

        registers = field(0, "registers");
        marks = layout.origins ? field(1, "register.marks") : nullptr;
        flags = field(2, "flags");
        directionFlag = ir.CreateInBoundsGEP(ir.getInt1Ty(), flags, ir.getInt32(FlagCount));
        instance = layout.runtime ? field(5, "runtime.instance") : nullptr;
        thread = layout.runtime ? field(6, "runtime.thread") : nullptr;
        bytes = layout.stack ? field(3, "stack.bytes") : nullptr;
        validity = layout.stack ? field(4, "stack.valid") : nullptr;
    }

    namespace {
        Value *slot(IRBuilder<> &ir, Value *array, unsigned i) {
            return ir.CreateInBoundsGEP(ir.getInt64Ty(), array, ir.getInt32(i));
        }

        uint64_t entryMarks(unsigned index, const Defined &definitions) {
            if (index <= rspIndex) {
                return definitions[index];
            }

            uint64_t marks = 0;

            for (unsigned byte = 0; byte < 8; ++byte) {
                const auto identity = (index - rspIndex - 1) * 8 + byte + 1;
                marks |= static_cast<uint64_t>(identity) << (8 * byte);
            }

            return marks;
        }

        void initializeRegisters(IRBuilder<> &ir, const ContextView &context, Value *state,
                                 ArrayRef<Value *> arguments, EntryMode mode) {
            const auto definitions = entryRegisterDefinitions(mode);

            for (unsigned i = 0; i < registerCount; ++i) {
                Value *value = ir.getInt64(0);

                if (state && i < callerSlots) {
                    value = ir.CreateAlignedLoad(ir.getInt64Ty(), slot(ir, state, i), Align(4));
                } else if (!arguments.empty() && (i == 1 || i == 2)) {
                    value = arguments[i - 1];
                } else if (i == rspIndex) {
                    value = ir.getInt64(GuestMemory::entryRsp);
                } else if (context.marks && i > rspIndex) {
                    value = ir.CreateFreeze(PoisonValue::get(ir.getInt64Ty()), "incoming");
                }

                ir.CreateStore(value, slot(ir, context.registers, i));

                if (context.marks) {
                    ir.CreateStore(ir.getInt64(entryMarks(i, definitions)),
                                   slot(ir, context.marks, i));
                }
            }

            // These backing bits can cross a flag-preserving callee. The data-flow
            // proof independently excludes any guest observation of an undefined bit.
            // The Windows ABI supplies a clear direction flag on external entry.
            auto *flags = ArrayType::get(ir.getInt1Ty(), FlagCount + 1);
            ir.CreateStore(ConstantAggregateZero::get(flags), context.flags);
        }

        void emitNativeWrapper(Function &adapter) {
            auto &module = *adapter.getParent();
            IRBuilder<> ir(module.getContext());
            auto *word = ir.getInt64Ty();
            auto *type = FunctionType::get(word, {word, word}, false);
            auto *native =
                Function::Create(type, Function::ExternalLinkage, "forge_lifted", module);
            ir.SetInsertPoint(BasicBlock::Create(ir.getContext(), "entry", native));
            auto *slots = ArrayType::get(word, callerSlots);
            auto *state = ir.CreateAlloca(slots);
            ir.CreateStore(ConstantAggregateZero::get(slots), state);
            ir.CreateStore(native->getArg(0), slot(ir, state, 1));
            ir.CreateStore(native->getArg(1), slot(ir, state, 2));
            ir.CreateCall(&adapter, state);
            ir.CreateRet(ir.CreateLoad(word, state));
        }

        Value *enterCheckedInvocation(IRBuilder<> &ir, Function &adapter, GuestMemory &memory,
                                      const ContextView &context, Value *image) {
            auto *word = ir.getInt64Ty();
            auto *pointer = ir.getPtrTy();
            Value *stack = ConstantPointerNull::get(pointer);

            if (context.bytes) {
                // forge_rt_stack borrows these two arrays until the outer adapter leaves.
                auto *type = StructType::get(word, word, pointer, pointer, word);
                stack = ir.CreateAlloca(type, nullptr, "stack.mapping");
                ir.CreateStore(ir.getInt64(GuestMemory::base), ir.CreateStructGEP(type, stack, 0));
                ir.CreateStore(ir.getInt64(GuestMemory::capacity),
                               ir.CreateStructGEP(type, stack, 1));
                ir.CreateStore(context.bytes, ir.CreateStructGEP(type, stack, 2));
                ir.CreateStore(context.validity, ir.CreateStructGEP(type, stack, 3));
                ir.CreateStore(ir.getInt64(GuestMemory::entryRsp),
                               ir.CreateStructGEP(type, stack, 4));
            }

            auto *handle = ir.CreateAlloca(word, nullptr, "active.invocation");
            auto enter = adapter.getParent()->getOrInsertFunction(
                "forge_rt_enter", ir.getInt32Ty(), pointer, word, pointer, pointer, pointer);
            auto *status =
                ir.CreateCall(enter, {adapter.getArg(0), adapter.getArg(1), image, stack, handle});
            memory.checks.guard(ir.CreateIsNull(status));
            return ir.CreateLoad(word, handle);
        }

        void checkOuterReturn(IRBuilder<> &ir, GuestMemory &memory, const ContextView &context,
                              const SavedRegisters &saved, bool checkStack) {
            if (checkStack) {
                if (context.marks) {
                    auto *marks = ir.CreateLoad(ir.getInt64Ty(), slot(ir, context.marks, rspIndex));
                    memory.checks.guard(ir.CreateICmpEQ(marks, ir.getInt64(UINT64_MAX)));
                }

                memory.checkReturn(
                    ir.CreateLoad(ir.getInt64Ty(), slot(ir, context.registers, rspIndex)));
            }

            checkNonvolatiles(ir, memory, context, saved);
        }

        void checkResultRegister(IRBuilder<> &ir, GuestMemory &memory, const ContextView &context) {
            if (context.marks) {
                auto *marks = ir.CreateLoad(ir.getInt64Ty(), context.marks);
                memory.checks.guard(ir.CreateICmpEQ(marks, ir.getInt64(UINT64_MAX)));
            }
        }

        void emitRuntimeReturn(IRBuilder<> &ir, Function &adapter, GuestMemory &memory,
                               const ContextView &context, Value *active) {
            checkResultRegister(ir, memory, context);

            if (active) {
                auto leave = adapter.getParent()->getOrInsertFunction(
                    "forge_rt_leave", ir.getInt32Ty(), ir.getPtrTy(), ir.getInt64Ty(),
                    ir.getInt64Ty());
                auto *status = ir.CreateCall(leave, {adapter.getArg(0), adapter.getArg(1), active});
                memory.checks.guard(ir.CreateIsNull(status));
            }

            ir.CreateRet(ir.CreateLoad(ir.getInt64Ty(), context.registers));
        }
    } // namespace

    SavedRegisters captureNonvolatiles(IRBuilder<> &ir, const ContextView &context,
                                       RegisterSet modified) {
        SavedRegisters saved{};

        for (unsigned i = rspIndex + 1; i < registerCount; ++i) {
            if (modified[i]) {
                saved[i] = {ir.CreateLoad(ir.getInt64Ty(), slot(ir, context.registers, i)),
                            ir.CreateLoad(ir.getInt64Ty(), slot(ir, context.marks, i))};
            }
        }

        return saved;
    }

    void checkNonvolatiles(IRBuilder<> &ir, GuestMemory &memory, const ContextView &context,
                           const SavedRegisters &saved) {
        for (unsigned i = rspIndex + 1; i < registerCount; ++i) {
            if (saved[i].bits) {
                auto *bits = ir.CreateLoad(ir.getInt64Ty(), slot(ir, context.registers, i));
                auto *marks = ir.CreateLoad(ir.getInt64Ty(), slot(ir, context.marks, i));
                memory.checks.guard(ir.CreateAnd(ir.CreateICmpEQ(bits, saved[i].bits),
                                                 ir.CreateICmpEQ(marks, saved[i].marks)));
            }
        }
    }

    Function *emitProcessEntry(Function &body, const RecoveredFunctionGroup &group,
                               const ContextLayout &layout, const ImagePlan &image,
                               RegisterSet modified, EntryMode mode) {
        auto &module = *body.getParent();
        IRBuilder<> ir(module.getContext());
        auto *type = FunctionType::get(ir.getVoidTy(), ir.getPtrTy(), false);
        auto *entry =
            Function::Create(type, Function::InternalLinkage, "forge_process_entry", module);
        auto *resolver = image.emitProcess(*entry, group);
        ir.SetInsertPoint(BasicBlock::Create(ir.getContext(), "entry", entry));
        auto *execution = entry->getArg(0);
        const ContextView context(ir, layout, execution);
        GuestMemory memory(ir);
        memory.bind(context.bytes, context.validity, resolver, context.regions);
        memory.checks.bind(context.result);
        auto *rcx = ir.CreateLoad(ir.getInt64Ty(),
                                  ir.CreateStructGEP(layout.type, execution, 5, "entry.rcx"));
        auto *rdx = ir.CreateLoad(ir.getInt64Ty(),
                                  ir.CreateStructGEP(layout.type, execution, 6, "entry.rdx"));
        initializeRegisters(ir, context, nullptr, {rcx, rdx}, mode);

        const auto saved = captureNonvolatiles(ir, context, modified);
        memory.checks.propagate(ir.CreateCall(&body, execution));
        checkOuterReturn(ir, memory, context, saved, true);
        checkResultRegister(ir, memory, context);
        memory.checks.complete(ir.CreateLoad(ir.getInt64Ty(), context.registers));
        return resolver;
    }

    Function *emitEntryAdapter(Function &body, uint32_t rva, EntryMode mode,
                               const ContextLayout &layout, const ImagePlan &image,
                               RegisterSet modified, bool checkedMemory) {
        auto &module = *body.getParent();
        IRBuilder<> ir(module.getContext());
        Function *adapter;
        Value *state = nullptr;
        if (layout.runtime) {
            auto *word = ir.getInt64Ty();
            auto *type = FunctionType::get(word, {ir.getPtrTy(), word, word, word}, false);
            adapter = Function::Create(type, Function::ExternalLinkage, "forge_lifted_with_runtime",
                                       module);
        } else {
            adapter = Function::Create(body.getFunctionType(), Function::InternalLinkage,
                                       "forge_lifted_" + utohexstr(rva, true), module);
            appendToUsed(module, {adapter});
            state = adapter->getArg(0);
            state->setName("state");
        }

        ir.SetInsertPoint(BasicBlock::Create(ir.getContext(), "entry", adapter));
        auto *invocation = ir.CreateAlloca(layout.type, nullptr, "invocation");
        const ContextView context(ir, layout, invocation);
        SmallVector<Value *, 2> arguments;
        if (layout.runtime) {
            arguments.append({adapter->getArg(2), adapter->getArg(3)});
            ir.CreateStore(adapter->getArg(0), context.instance);
            ir.CreateStore(adapter->getArg(1), context.thread);
        }

        initializeRegisters(ir, context, state, arguments, mode);
        GuestMemory memory(ir);
        const auto emitted = image.emit(module, ir, checkedMemory);

        if (context.bytes) {
            memory.initialize(context.bytes, context.validity);
        }

        Value *active = nullptr;

        if (emitted.descriptorAccessor) {
            auto *imageDescriptor = ir.CreateCall(emitted.descriptorAccessor);
            active = enterCheckedInvocation(ir, *adapter, memory, context, imageDescriptor);
        }

        const bool typed = mode == EntryMode::WindowsX64I64Pair;
        const auto saved = captureNonvolatiles(ir, context, typed ? modified : RegisterSet{});
        ir.CreateCall(&body, invocation);

        checkOuterReturn(ir, memory, context, saved, layout.stack || modified[rspIndex]);

        if (layout.runtime) {
            emitRuntimeReturn(ir, *adapter, memory, context, active);
            return emitted.resolver;
        }

        for (unsigned i = 0; i < callerSlots; ++i) {
            if (context.marks && (!typed || i == 0)) {
                auto *marks = ir.CreateLoad(ir.getInt64Ty(), slot(ir, context.marks, i));
                memory.checks.guard(ir.CreateICmpEQ(marks, ir.getInt64(UINT64_MAX)));
            }

            auto *value = ir.CreateLoad(ir.getInt64Ty(), slot(ir, context.registers, i));
            ir.CreateAlignedStore(value, slot(ir, state, i), Align(4));
        }

        ir.CreateRetVoid();

        if (typed) {
            emitNativeWrapper(*adapter);
        }

        return emitted.resolver;
    }
} // namespace forge::x86
