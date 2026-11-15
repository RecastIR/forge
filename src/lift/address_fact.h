#pragma once

#include "lift/memory.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallVector.h"

#include <bit>
#include <map>

namespace forge::x86 {
    // Guest integer alternatives are sorted, unique, and wrap at 64 bits. The
    // empty set denotes unknown. Widening bounds both loop convergence and storage.
    class AddressFact {
      public:
        enum Origin : uint8_t { Computed, Constant, Stack };

        static constexpr unsigned limit = 8;

        AddressFact() = default;

        explicit AddressFact(uint64_t value, Origin provenance = Constant)
            : addresses{value}, origin(provenance) {}

        bool operator==(const AddressFact &) const = default;

        llvm::ArrayRef<uint64_t> values() const { return addresses; }

        bool known() const { return !addresses.empty(); }

        bool stackDerived() const { return origin == Stack; }

        // Only the original single-origin proof can constrain an out-of-stack
        // arithmetic result to the checked stack path. Newly proved alternatives
        // guide image selection while retaining dispatch by the resulting VA.
        AddressFact computed() const {
            auto result = *this;
            result.origin = Computed;
            return result;
        }

        AddressFact join(const AddressFact &other) const {
            if (!known() || !other.known()) {
                return {};
            }

            if (*this == other) {
                return *this;
            }

            auto result = computed();
            if (!result.includeOffsets(0, other)) {
                return {};
            }

            return result;
        }

        AddressFact plus(const AddressFact &other) const {
            AddressFact result;
            for (auto lhs : addresses) {
                if (!result.includeOffsets(lhs, other)) {
                    return {};
                }
            }

            if (origin == Constant) {
                result.origin = other.origin;
            } else if (other.origin == Constant) {
                result.origin = origin;
            }

            return result;
        }

        AddressFact times(uint64_t factor) const {
            if (factor == 1) {
                return *this;
            }

            AddressFact result;
            for (auto value : addresses) {
                result.include(value * factor);
            }

            if (origin == Constant) {
                result.origin = Constant;
            }

            return result;
        }

        AddressFact masked(uint64_t mask) const {
            AddressFact result;
            if (known()) {
                for (auto value : addresses) {
                    result.include(value & mask);
                }

                return result;
            }

            // An unconstrained input can produce all 2^popcount(mask) submasks.
            if (std::popcount(mask) >= static_cast<int>(std::bit_width(limit))) {
                return {};
            }

            auto submask = mask;
            for (;;) {
                result.include(submask);

                if (submask == 0) {
                    return result;
                }

                submask = (submask - 1) & mask;
            }
        }

      private:
        llvm::SmallVector<uint64_t, 1> addresses;
        Origin origin = Computed;

        bool includeOffsets(uint64_t base, const AddressFact &offsets) {
            for (auto offset : offsets.addresses) {
                if (!include(base + offset)) {
                    return false;
                }
            }

            return true;
        }

        bool include(uint64_t value) {
            auto pos = llvm::lower_bound(addresses, value);
            if (pos != addresses.end() && *pos == value) {
                return true;
            }

            if (addresses.size() == limit) {
                return false;
            }

            addresses.insert(pos, value);
            return true;
        }
    };

    // Slots are exact, nonoverlapping eight-byte saves within one invocation's
    // stack. Both RSP-derived and absolute numeric aliases use the same guest VA.
    class StackSpills {
      public:
        bool merge(const StackSpills &other) {
            bool changed = false;
            for (auto it = slots.begin(); it != slots.end();) {
                const auto incoming = other.slots.find(it->first);
                auto value = incoming == other.slots.end() ? AddressFact{}
                                                           : it->second.join(incoming->second);
                if (!value.known()) {
                    it = slots.erase(it);
                    changed = true;
                } else {
                    changed |= it->second != value;
                    it->second = std::move(value);
                    ++it;
                }
            }

            return changed;
        }

        AddressFact read(const AddressFact &address) const {
            AddressFact result;
            for (auto va : address.values()) {
                const auto it = slots.find(va);
                if (it == slots.end()) {
                    return {};
                }

                result = result.known() ? result.join(it->second) : it->second;
                if (!result.known()) {
                    return {};
                }
            }

            return result;
        }

        void write(const AddressFact &address, unsigned width, const AddressFact &value) {
            if (!address.known()) {
                slots.clear();
                return;
            }

            const unsigned bytes = width / 8;
            for (auto va : address.values()) {
                if (va - GuestMemory::base >= GuestMemory::capacity) {
                    continue;
                }

                slots.erase(slots.lower_bound(va - 7), slots.lower_bound(va + bytes));
                if (address.values().size() == 1 && width == 64 && value.known() &&
                    va - GuestMemory::base <= GuestMemory::capacity - bytes) {
                    slots.emplace(va, value.computed());
                }
            }
        }

      private:
        std::map<uint64_t, AddressFact> slots;
    };
} // namespace forge::x86
