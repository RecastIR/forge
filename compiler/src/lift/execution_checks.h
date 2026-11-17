#pragma once

#include "forge/process.h"

#include "llvm/IR/IRBuilder.h"

namespace forge::x86 {
    llvm::StructType *memoryFaultType(llvm::LLVMContext &context);
    llvm::StructType *processResultType(llvm::LLVMContext &context);

    // Function entries trap. Process entries write one terminal result and unwind
    // nested guest bodies through a failure return before executing a continuation.
    class ExecutionChecks {
      public:
        explicit ExecutionChecks(llvm::IRBuilder<> &builder) : ir(builder) {}

        void bind(llvm::Value *output) { result = output; }

        bool managed() const { return result != nullptr; }

        void guard(llvm::Value *condition, uint32_t fault = FORGE_RT_FAULT_ABI);
        void scalarBoundary(llvm::Value *condition, llvm::Value *address, unsigned size,
                            uint32_t access, bool stack);
        void stackMarks(llvm::Value *allowed, llvm::Value *offset, uint32_t access);
        void service(llvm::Value *status, llvm::Value *detail);
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
        void returnFailure();
    };
} // namespace forge::x86
