#pragma once

#include "lift/memory.h"

#include "llvm/ADT/SmallVector.h"

#include <compare>
#include <map>
#include <memory>
#include <optional>

namespace forge::x86 {
    // A group represents all resolved call sites entering one callee. Keep their
    // shared displacement symbolic until a guest access actually needs PE bytes.
    struct Continuation {
        uint32_t callee;
        uint64_t offset;
        auto operator<=>(const Continuation &) const = default;
    };

    class AddressFact {
      public:
        enum Origin : uint8_t { Computed, Constant, Stack, FrameStack };

        static constexpr unsigned limit = 8;

        AddressFact() = default;

        explicit AddressFact(uint64_t value, Origin provenance = Constant)
            : addresses{value}, origin(provenance), unknown(false) {}

        bool operator==(const AddressFact &) const = default;

        llvm::ArrayRef<uint64_t> values() const { return addresses; }

        llvm::ArrayRef<Continuation> continuations() const { return returns; }

        bool known() const { return !unknown && returns.empty() && !addresses.empty(); }

        bool hasUnknown() const { return unknown; }

        // Widened symbolic alternatives must survive a loop join even though
        // they authorize no new executable bytes.
        bool tracksSpill() const {
            return !unknown || displacement || !returns.empty() || widenedReturns;
        }

        static AddressFact frameStack(uint64_t offset = 0);
        static AddressFact continuation(uint32_t callee);

        std::optional<uint64_t> frameOffset() const { return displacement; }

        bool stackDerived() const { return origin == Stack || origin == FrameStack; }

        AddressFact computed() const;
        AddressFact project(const AddressFact &entryRsps) const;
        AddressFact reloaded(const AddressFact &entryRsps) const;
        AddressFact join(const AddressFact &other) const;
        AddressFact joinInFrame(const AddressFact &other, const AddressFact &entryRsps) const;
        AddressFact plus(const AddressFact &other) const;
        AddressFact times(uint64_t factor) const;
        AddressFact masked(uint64_t mask) const;

      private:
        llvm::SmallVector<uint64_t, 1> addresses;
        llvm::SmallVector<Continuation, 1> returns;
        // A reloaded pointer keeps its frame coordinate for alias analysis while
        // ordinary dereferences use its computed VAs and the dynamic resolver.
        std::optional<uint64_t> displacement;
        Origin origin = Computed;
        bool unknown = true;
        // Widening is absorbing at a join, including on a loop backedge.
        bool widenedReturns = false;

        void includeAddress(uint64_t va);
        void includeReturn(Continuation source);
        AddressFact addOffsets(const AddressFact &offsets) const;
    };

    // Slots describe DWORD and QWORD saves. Distinct CFG paths can save at overlapping
    // offsets, so a store must invalidate every overlap. Keys use either absolute
    // stack VAs or signed offsets from the current activation's entry RSP. A
    // write using one coordinate system may alias saves in the other.
    class StackSpills {
      public:
        // The returned fact is borrowed until this snapshot is modified.
        const AddressFact *find(uint64_t va) const;
        bool merge(const StackSpills &other, const AddressFact &entryRsps = {});
        AddressFact read(const AddressFact &address, const AddressFact &entryRsps = {},
                         unsigned width = 64) const;
        void write(const AddressFact &address, unsigned width, const AddressFact &value);

      private:
        struct Saved {
            AddressFact value;
            unsigned width = 64;

            bool operator==(const Saved &) const = default;
            AddressFact read(unsigned bits, const AddressFact &entryRsps) const;
            Saved join(const Saved &other, const AddressFact &entryRsps) const;
        };

        using Slots = std::map<int64_t, Saved>;
        using Snapshot = std::shared_ptr<Slots>;
        Snapshot absolute, relative;

        static const Saved *lookup(const Snapshot &slots, int64_t key);
        static Slots &writable(Snapshot &slots);
        static bool mergeSlots(Snapshot &slots, const Snapshot &incoming,
                               const AddressFact &entryRsps);
        static void replace(Snapshot &slots, int64_t key, unsigned bytes, const Saved &saved);
    };
} // namespace forge::x86
