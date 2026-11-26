#pragma once

#include "forge/process.h"

#include "llvm/IR/IRBuilder.h"

namespace forge::x86 {
    llvm::StructType *memoryFaultType(llvm::LLVMContext &context);
    llvm::StructType *processResultType(llvm::LLVMContext &context);

    // Function entries trap. A managed body returns false for any terminal result,
    // propagating it through every caller before executing a guest continuation.
    class ExecutionChecks {
      public:
        explicit ExecutionChecks(llvm::IRBuilder<> &builder) : ir(builder) {}

        void bind(llvm::Value *output) { result = output; }

        bool managed() const { return result != nullptr; }

        uint64_t tableOrigin = 0;
        void guard(llvm::Value *condition, uint32_t fault = FORGE_RT_FAULT_ABI);
        void requireSupported(llvm::Value *condition, forge_rt_status status = FORGE_RT_OK);
        void unsupported(forge_rt_status status);
        void scalarBoundary(llvm::Value *condition, llvm::Value *address, unsigned size,
                            uint32_t access, bool stack);
        llvm::Value *processScalar(llvm::Value *imageBytes, llvm::Value *address, unsigned size,
                                   uint32_t access);
        void stackMarks(llvm::Value *allowed, llvm::Value *offset, uint32_t access);
        void service(llvm::Value *status, llvm::Value *detail);
        void propagatePending();
        void propagate(llvm::Value *returned);
        void fail(uint32_t fault);
        void complete(llvm::Value *rax);

      private:
        llvm::IRBuilder<> &ir;
        llvm::Value *result = nullptr;
        llvm::BasicBlock *trap = nullptr;
        llvm::Value *field(unsigned index);
        void onFailure(llvm::Value *condition, llvm::function_ref<void()> record);
        void recordFault(uint32_t fault);
        void recordUnsupported(forge_rt_status status);
        void returnFailure();
    };
} // namespace forge::x86
