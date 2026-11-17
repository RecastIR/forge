#include "lift/execution_checks.h"

#include "llvm/IR/Intrinsics.h"

namespace forge::x86 {
    using namespace llvm;

    StructType *memoryFaultType(LLVMContext &context) {
        auto *word = Type::getInt32Ty(context);
        return StructType::get(Type::getInt64Ty(context), word, word);
    }

    StructType *processResultType(LLVMContext &context) {
        auto *word = Type::getInt32Ty(context);
        return StructType::get(word, word, Type::getInt64Ty(context), memoryFaultType(context),
                               word);
    }

    Value *ExecutionChecks::field(unsigned index) {
        return ir.CreateStructGEP(processResultType(ir.getContext()), result, index);
    }

    void ExecutionChecks::returnFailure() {
        if (ir.GetInsertBlock()->getParent()->getReturnType()->isVoidTy()) {
            ir.CreateRetVoid();
        } else {
            ir.CreateRet(ir.getFalse());
        }
    }

    void ExecutionChecks::recordFault(uint32_t fault) {
        ir.CreateStore(ir.getInt32(FORGE_RT_EXECUTION_FAULT), field(0));
        ir.CreateStore(ir.getInt32(FORGE_RT_GUEST_FAULT), field(1));
        ir.CreateStore(ir.getInt32(fault), field(4));
    }

    void ExecutionChecks::fail(uint32_t fault) {
        if (managed()) {
            recordFault(fault);
            returnFailure();
        } else {
            ir.CreateIntrinsic(Intrinsic::trap, {});
            ir.CreateUnreachable();
        }
    }

    void ExecutionChecks::onFailure(Value *condition, function_ref<void()> record) {
        auto *function = ir.GetInsertBlock()->getParent();
        auto *failure = trap;

        if (!failure) {
            IRBuilderBase::InsertPointGuard restore(ir);
            failure = BasicBlock::Create(ir.getContext(), "stack.fault", function);
            ir.SetInsertPoint(failure);

            if (managed()) {
                record();
                returnFailure();
            } else {
                trap = failure;
                fail(FORGE_RT_FAULT_ABI);
            }
        }

        auto *next = BasicBlock::Create(ir.getContext(), "stack.ok", function);
        ir.CreateCondBr(condition, next, failure);
        ir.SetInsertPoint(next);
    }

    void ExecutionChecks::guard(Value *condition, uint32_t fault) {
        onFailure(condition, [&] { recordFault(fault); });
    }

    void ExecutionChecks::memory(Value *condition, Value *address, uint32_t access, Value *reason,
                                 Value *invalidLanes) {
        onFailure(condition, [&] {
            recordFault(FORGE_RT_FAULT_MEMORY);
            auto *type = memoryFaultType(ir.getContext());
            auto *detail = field(3);

            if (invalidLanes) {
                // The failure edge has at least one invalid byte. The guest and target
                // are little endian, so its first byte is the mask's lowest set bit.
                const auto width = cast<FixedVectorType>(invalidLanes->getType())->getNumElements();
                auto *bits = ir.CreateBitCast(invalidLanes, ir.getIntNTy(width));
                auto *first =
                    ir.CreateIntrinsic(Intrinsic::cttz, {bits->getType()}, {bits, ir.getTrue()});
                address = ir.CreateAdd(address, ir.CreateZExt(first, ir.getInt64Ty()));
            }

            ir.CreateStore(address, ir.CreateStructGEP(type, detail, 0));
            ir.CreateStore(ir.getInt32(access), ir.CreateStructGEP(type, detail, 1));
            ir.CreateStore(reason, ir.CreateStructGEP(type, detail, 2));
        });
    }

    void ExecutionChecks::service(Value *status, Value *detail) {
        onFailure(ir.CreateIsNull(status), [&] {
            if (detail) {
                auto *function = ir.GetInsertBlock()->getParent();
                auto *guest = BasicBlock::Create(ir.getContext(), "service.guest.fault", function);
                auto *native = BasicBlock::Create(ir.getContext(), "service.failure", function);
                ir.CreateCondBr(ir.CreateICmpEQ(status, ir.getInt32(FORGE_RT_GUEST_FAULT)), guest,
                                native);
                ir.SetInsertPoint(guest);
                recordFault(FORGE_RT_FAULT_MEMORY);
                ir.CreateStore(ir.CreateLoad(memoryFaultType(ir.getContext()), detail), field(3));
                returnFailure();
                ir.SetInsertPoint(native);
            }

            ir.CreateStore(ir.getInt32(FORGE_RT_RUNTIME_FAILURE), field(0));
            ir.CreateStore(status, field(1));
        });
    }

    void ExecutionChecks::propagate(Value *returned) {
        if (managed()) {
            onFailure(returned, [] {});
        }
    }

    void ExecutionChecks::complete(Value *rax) {
        ir.CreateStore(ir.getInt32(FORGE_RT_RETURNED), field(0));
        ir.CreateStore(ir.getInt32(FORGE_RT_OK), field(1));
        ir.CreateStore(rax, field(2));
        ir.CreateRetVoid();
    }
} // namespace forge::x86
