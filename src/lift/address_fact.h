#pragma once

#include "lift/memory.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallVector.h"

#include <bit>
#include <map>
#include <memory>

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
    // stack. CFG states share the map until a write or join changes its contents.
    class StackSpills {
      public:
        // The returned fact is borrowed until this snapshot is modified.
        const AddressFact *find(uint64_t va) const {
            if (!slots) {
                return nullptr;
            }

            const auto it = slots->find(va);
            return it == slots->end() ? nullptr : &it->second;
        }

        bool merge(const StackSpills &other) {
            if (!slots || slots == other.slots) {
                return false;
            }

            if (!other.slots) {
                slots.reset();
                return true;
            }

            auto joined = [&other](const auto &slot) {
                const auto *incoming = other.find(slot.first);
                return incoming ? slot.second.join(*incoming) : AddressFact{};
            };
            const auto first = llvm::find_if(
                *slots, [&](const auto &slot) { return joined(slot) != slot.second; });
            if (first == slots->end()) {
                return false;
            }

            // Reacquire iterators in the detached map. All preceding slots agree.
            const auto va = first->first;
            auto &updated = writable();
            for (auto it = updated.lower_bound(va); it != updated.end();) {
                auto value = joined(*it);
                if (!value.known()) {
                    it = updated.erase(it);
                } else {
                    it->second = std::move(value);
                    ++it;
                }
            }

            if (updated.empty()) {
                slots.reset();
            }

            return true;
        }

        AddressFact read(const AddressFact &address) const {
            AddressFact result;
            for (auto va : address.values()) {
                const auto *saved = find(va);
                if (!saved) {
                    return {};
                }

                result = result.known() ? result.join(*saved) : *saved;
                if (!result.known()) {
                    return {};
                }
            }

            return result;
        }

        void write(const AddressFact &address, unsigned width, const AddressFact &value) {
            if (!address.known()) {
                slots.reset();
                return;
            }

            const unsigned bytes = width / 8;
            for (auto va : address.values()) {
                if (va - GuestMemory::base >= GuestMemory::capacity) {
                    continue;
                }

                const bool exact = address.values().size() == 1 && width == 64 &&
                                   va - GuestMemory::base <= GuestMemory::capacity - bytes;
                replace(va, bytes, exact ? value.computed() : AddressFact{});
            }
        }

      private:
        using Slots = std::map<uint64_t, AddressFact>;
        std::shared_ptr<Slots> slots;

        Slots &writable() {
            if (!slots) {
                slots = std::make_shared<Slots>();
            } else if (slots.use_count() > 1) {
                slots = std::make_shared<Slots>(*slots);
            }

            return *slots;
        }

        void replace(uint64_t va, unsigned bytes, const AddressFact &saved) {
            if (slots) {
                const auto it = slots->lower_bound(va - 7);
                const bool overlaps = it != slots->end() && it->first < va + bytes;
                if ((!overlaps && !saved.known()) ||
                    (overlaps && it->first == va && it->second == saved)) {
                    return;
                }
            } else if (!saved.known()) {
                return;
            }

            auto &updated = writable();
            updated.erase(updated.lower_bound(va - 7), updated.lower_bound(va + bytes));
            if (saved.known()) {
                updated.emplace(va, saved);
            } else if (updated.empty()) {
                slots.reset();
            }
        }
    };
} // namespace forge::x86
