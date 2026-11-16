#include "lift/execution_context.h"
#include "lift/image_memory.h"

#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

namespace forge::x86 {
    using namespace llvm;

    ContextLayout::ContextLayout(LLVMContext &context, bool origins, bool stack, bool runtime)
        : origins(origins), stack(stack), runtime(runtime) {
        const auto registers = [&](unsigned count) {
            return ArrayType::get(Type::getInt64Ty(context), count);
        };
        auto *stackType =
            ArrayType::get(Type::getInt8Ty(context), stack ? GuestMemory::capacity : 0);
        auto *flagType = ArrayType::get(Type::getInt1Ty(context), FlagCount);
        SmallVector<Type *> fields{registers(registerCount), registers(origins ? registerCount : 0),
                                   flagType, stackType, stackType};
        if (runtime) {
            fields.push_back(PointerType::getUnqual(context));
            fields.push_back(Type::getInt64Ty(context));
        }

        type = StructType::get(context, fields);
    }

    ContextView::ContextView(IRBuilder<> &ir, const ContextLayout &layout, Value *context)
        : registers(ir.CreateStructGEP(layout.type, context, 0, "registers")),
          marks(layout.origins ? ir.CreateStructGEP(layout.type, context, 1, "register.marks")
                               : nullptr),
          flags(ir.CreateStructGEP(layout.type, context, 2, "flags")),
          instance(layout.runtime ? ir.CreateStructGEP(layout.type, context, 5, "runtime.instance")
                                  : nullptr),
          thread(layout.runtime ? ir.CreateStructGEP(layout.type, context, 6, "runtime.thread")
                                : nullptr),
          bytes(layout.stack ? ir.CreateStructGEP(layout.type, context, 3, "stack.bytes")
                             : nullptr),
          validity(layout.stack ? ir.CreateStructGEP(layout.type, context, 4, "stack.valid")
                                : nullptr) {}

    namespace {
        Value *slot(IRBuilder<> &ir, Value *array, unsigned i) {
            return ir.CreateInBoundsGEP(ir.getInt64Ty(), array, ir.getInt32(i));
        }

        uint64_t entryMarks(unsigned index) {
            if (index <= rspIndex) {
                return UINT64_MAX;
            }

            uint64_t marks = 0;

            for (unsigned byte = 0; byte < 8; ++byte) {
                const auto identity = (index - rspIndex - 1) * 8 + byte + 1;
                marks |= static_cast<uint64_t>(identity) << (8 * byte);
            }

            return marks;
        }

        void initializeRegisters(IRBuilder<> &ir, const ContextView &context, Value *state,
                                 Function &adapter) {
            for (unsigned i = 0; i < registerCount; ++i) {
                Value *value = ir.getInt64(0);

                if (state && i < callerSlots) {
                    value = ir.CreateAlignedLoad(ir.getInt64Ty(), slot(ir, state, i), Align(4));
                } else if (!state && (i == 1 || i == 2)) {
                    value = adapter.getArg(i + 1);
                } else if (i == rspIndex) {
                    value = ir.getInt64(GuestMemory::entryRsp);
                } else if (context.marks && i > rspIndex) {
                    value = ir.CreateFreeze(PoisonValue::get(ir.getInt64Ty()), "incoming");
                }

                ir.CreateStore(value, slot(ir, context.registers, i));

                if (context.marks) {
                    ir.CreateStore(ir.getInt64(entryMarks(i)), slot(ir, context.marks, i));
                }
            }

            // These backing bits can cross a flag-preserving callee. The data-flow
            // proof independently excludes any guest observation of an undefined bit.
            auto *flags = ArrayType::get(ir.getInt1Ty(), FlagCount);
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
                memory.guard(ir.CreateAnd(ir.CreateICmpEQ(bits, saved[i].bits),
                                          ir.CreateICmpEQ(marks, saved[i].marks)));
            }
        }
    }

    Function *emitEntryAdapter(Function &body, uint32_t rva, EntryMode mode,
                               const ContextLayout &layout, const ImagePlan &image,
                               RegisterSet modified) {
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
        if (layout.runtime) {
            ir.CreateStore(adapter->getArg(0), context.instance);
            ir.CreateStore(adapter->getArg(1), context.thread);
        }

        initializeRegisters(ir, context, state, *adapter);
        GuestMemory memory(ir);
        auto *resolver = image.emitResolver(module, ir);

        if (context.bytes) {
            memory.initialize(context.bytes, context.validity);
        }

        const bool typed = mode == EntryMode::WindowsX64I64Pair;
        const auto saved = captureNonvolatiles(ir, context, typed ? modified : RegisterSet{});
        ir.CreateCall(&body, invocation);

        if (layout.stack || modified[rspIndex]) {
            if (context.marks) {
                auto *marks = ir.CreateLoad(ir.getInt64Ty(), slot(ir, context.marks, rspIndex));
                memory.guard(ir.CreateICmpEQ(marks, ir.getInt64(UINT64_MAX)));
            }

            memory.checkReturn(
                ir.CreateLoad(ir.getInt64Ty(), slot(ir, context.registers, rspIndex)));
        }

        checkNonvolatiles(ir, memory, context, saved);

        if (layout.runtime) {
            if (context.marks) {
                auto *marks = ir.CreateLoad(ir.getInt64Ty(), context.marks);
                memory.guard(ir.CreateICmpEQ(marks, ir.getInt64(UINT64_MAX)));
            }

            ir.CreateRet(ir.CreateLoad(ir.getInt64Ty(), context.registers));
            return resolver;
        }

        for (unsigned i = 0; i < callerSlots; ++i) {
            if (context.marks && (!typed || i == 0)) {
                auto *marks = ir.CreateLoad(ir.getInt64Ty(), slot(ir, context.marks, i));
                memory.guard(ir.CreateICmpEQ(marks, ir.getInt64(UINT64_MAX)));
            }

            auto *value = ir.CreateLoad(ir.getInt64Ty(), slot(ir, context.registers, i));
            ir.CreateAlignedStore(value, slot(ir, state, i), Align(4));
        }

        ir.CreateRetVoid();

        if (typed) {
            emitNativeWrapper(*adapter);
        }

        return resolver;
    }
} // namespace forge::x86
