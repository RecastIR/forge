#pragma once

#include "lift/call_flow.h"
#include "lift/lift.h"
#include "lift/memory.h"

namespace forge::x86 {
    class ImagePlan;
    class RecoveredFunctionGroup;

    // LLVM owns the layout and all emitted storage. An external activation owns
    // one instance, and every guest body borrows it through its sole argument.
    struct ContextLayout {
        ContextLayout(llvm::LLVMContext &context, bool origins, bool stack, bool runtime,
                      bool process = false, bool callbacks = false, bool tailJumps = false);
        llvm::StructType *type;
        bool origins, stack, runtime, process;
        // Private guest-body arguments shared by all members of this group.
        bool callbacks, tailJumps;
        llvm::CallInst *callBody(llvm::IRBuilder<> &ir, llvm::Function &body,
                                 llvm::Value *execution, llvm::Value *frameRsp,
                                 llvm::Value *ceiling, uint32_t origin = 0) const;
    };

    struct ContextView {
        ContextView() = default;
        ContextView(llvm::IRBuilder<> &ir, const ContextLayout &layout, llvm::Value *context);
        llvm::Value *registers = nullptr, *marks = nullptr, *flags = nullptr;
        llvm::Value *directionFlag = nullptr;
        llvm::Value *instance = nullptr, *thread = nullptr;
        llvm::Value *bytes = nullptr, *validity = nullptr;
        llvm::Value *regions = nullptr, *result = nullptr;
    };

    using SavedRegisters = std::array<StoredValue, registerCount>;
    SavedRegisters captureNonvolatiles(llvm::IRBuilder<> &ir, const ContextView &context,
                                       RegisterSet modified);
    void checkNonvolatiles(llvm::IRBuilder<> &ir, GuestMemory &memory, const ContextView &context,
                           const SavedRegisters &saved);
    llvm::Function *emitInitializerThunk(llvm::Function &body, const ContextLayout &layout,
                                         RegisterSet modified);

    // Uses the process-owned execution view and emits its immutable artifact descriptor.
    llvm::Function *emitProcessEntry(llvm::Function &body, const RecoveredFunctionGroup &group,
                                     const ContextLayout &layout, const ImagePlan &image,
                                     RegisterSet modified, EntryMode mode);

    // Emits both selected-entry interfaces and the invocation-scoped initialization.
    llvm::Function *emitEntryAdapter(llvm::Function &body, uint32_t rva, EntryMode mode,
                                     const ContextLayout &layout, const ImagePlan &image,
                                     RegisterSet modified, bool checkedMemory);
} // namespace forge::x86
