#pragma once

#include "lift/execution_checks.h"

#include <cstdint>

namespace forge::x86 {
    // Each byte has a mark: zero for uninitialized, 0xff for concrete, or an
    // incoming nonvolatile byte identity. A null marks operand denotes all concrete.
    struct StoredValue {
        llvm::Value *bits;
        llvm::Value *marks = nullptr;
    };

    // Stack bytes, marks and image rows are borrowed from the active entry context.
    class GuestMemory {
      public:
        static constexpr uint64_t base = FORGE_RT_STACK_BASE;
        static constexpr unsigned capacity = FORGE_RT_STACK_SIZE;
        static constexpr uint64_t entryRsp = FORGE_RT_ENTRY_RSP;

        explicit GuestMemory(llvm::IRBuilder<> &builder) : checks(builder), ir(builder) {}

        ExecutionChecks checks;

        // Only the entry adapter initializes storage. Each body binds views
        // into the same invocation without clearing bytes or origin marks.
        void initialize(llvm::Value *stackBytes, llvm::Value *stackValidity);
        void bind(llvm::Value *stackBytes, llvm::Value *stackValidity, llvm::Function *resolver,
                  llvm::Value *regions = nullptr);
        llvm::Value *load(llvm::Value *address, unsigned width, bool stackOnly);
        StoredValue loadSaved(llvm::Value *address, unsigned width, bool stackOnly);
        void store(llvm::Value *address, StoredValue value, bool stackOnly);
        void modify(llvm::Value *address, unsigned width, bool stackOnly,
                    llvm::function_ref<llvm::Value *(llvm::Value *)> operation);
        void checkReturn(llvm::Value *rsp);
        // Keep the pushed entry RSP in the caller's native activation and use
        // that same value for popReturn, even when guest code has changed RSP.
        llvm::Value *pushReturn(llvm::Value *callRsp, llvm::Value *callerEntryRsp,
                                uint64_t nextGuestVA);
        llvm::Value *popReturn(llvm::Value *rsp, llvm::Value *expectedEntryRsp,
                               uint64_t nextGuestVA);

      private:
        llvm::IRBuilder<> &ir;
        llvm::Value *bytes = nullptr;
        llvm::Value *validity = nullptr;
        llvm::Value *regions = nullptr;

        llvm::Function *imageResolver = nullptr;

        enum class Access : uint32_t {
            Read = FORGE_RT_READ,
            ReadSaved = FORGE_RT_SCALAR_READ_SAVED,
            Write = FORGE_RT_WRITE,
            Modify = FORGE_RT_READ | FORGE_RT_WRITE
        };

        struct Location {
            llvm::Value *data;
            // Saved byte identities are only needed for plain copies.
            llvm::Value *marks = nullptr;
        };

        Location resolve(llvm::Value *address, unsigned width, Access access, bool stackOnly,
                         llvm::Value *storeMarks = nullptr);
        llvm::Value *checkedOffset(llvm::Value *address, unsigned width, Access access);
        void installReturn(llvm::Value *offset, uint64_t address);
        void verifyReturn(llvm::Value *offset, uint64_t address);
        Location stackLocation(llvm::Value *offset, unsigned width, Access access,
                               llvm::Value *storeMarks = nullptr);
    };
} // namespace forge::x86
