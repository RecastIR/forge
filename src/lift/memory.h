#pragma once

#include "llvm/IR/IRBuilder.h"

#include <cstdint>

namespace forge::x86 {
    // Each byte has a mark: zero for uninitialized, 0xff for concrete, or an
    // incoming nonvolatile byte identity. A null marks operand denotes all concrete.
    struct StoredValue {
        llvm::Value *bits;
        llvm::Value *marks = nullptr;
    };

    // Each invocation owns its stack. The image resolver borrows the module's
    // persistent storage. Guard continuations share the lowering builder.
    class GuestMemory {
      public:
        static constexpr uint64_t base = 0x70000000;
        static constexpr unsigned capacity = 4096;
        static constexpr uint64_t entryRsp = base + capacity - 32 - 8;

        explicit GuestMemory(llvm::IRBuilder<> &builder) : ir(builder) {}

        void allocate(llvm::Function *resolver);
        llvm::Value *load(llvm::Value *address, unsigned width, bool stackOnly);
        StoredValue loadSaved(llvm::Value *address, unsigned width, bool stackOnly);
        void store(llvm::Value *address, StoredValue value, bool stackOnly);
        void modify(llvm::Value *address, unsigned width, bool stackOnly,
                    llvm::function_ref<llvm::Value *(llvm::Value *)> operation);
        void checkReturn(llvm::Value *rsp);
        void guard(llvm::Value *condition);

      private:
        llvm::IRBuilder<> &ir;
        llvm::Value *bytes = nullptr;
        llvm::Value *validity = nullptr;
        llvm::BasicBlock *fault = nullptr;

        llvm::Function *imageResolver = nullptr;

        enum class Access { Read, ReadSaved, Write, Modify };

        struct Location {
            llvm::Value *data;
            // Saved byte identities are only needed for plain copies.
            llvm::Value *marks = nullptr;
        };

        Location resolve(llvm::Value *address, unsigned width, Access access, bool stackOnly,
                         llvm::Value *storeMarks = nullptr);
        llvm::Value *checkedOffset(llvm::Value *address, unsigned width);
        Location stackLocation(llvm::Value *offset, unsigned width, Access access,
                               llvm::Value *storeMarks = nullptr);
    };
} // namespace forge::x86
