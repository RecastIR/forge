#pragma once

#include "lift/call_flow.h"
#include "lift/lift.h"
#include "lift/memory.h"

namespace forge::x86 {
    class ImagePlan;

    // LLVM owns the layout and all emitted storage. An external activation owns
    // one instance, and every guest body borrows it through its sole argument.
    struct ContextLayout {
        ContextLayout(llvm::LLVMContext &context, bool origins, bool stack, bool runtime);
        llvm::StructType *type;
        bool origins, stack, runtime;
    };

    struct ContextView {
        ContextView() = default;
        ContextView(llvm::IRBuilder<> &ir, const ContextLayout &layout, llvm::Value *context);
        llvm::Value *registers = nullptr, *marks = nullptr, *flags = nullptr;
        llvm::Value *instance = nullptr, *thread = nullptr;
        llvm::Value *bytes = nullptr, *validity = nullptr;
    };

    using SavedRegisters = std::array<StoredValue, registerCount>;
    SavedRegisters captureNonvolatiles(llvm::IRBuilder<> &ir, const ContextView &context,
                                       RegisterSet modified);
    void checkNonvolatiles(llvm::IRBuilder<> &ir, GuestMemory &memory, const ContextView &context,
                           const SavedRegisters &saved);

    // Emits both selected-entry interfaces and the invocation-scoped initialization.
    llvm::Function *emitEntryAdapter(llvm::Function &body, uint32_t rva, EntryMode mode,
                                     const ContextLayout &layout, const ImagePlan &image,
                                     RegisterSet modified);
} // namespace forge::x86
