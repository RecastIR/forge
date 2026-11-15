#include "lift/address_fact.h"

#include "llvm/ADT/STLExtras.h"

#include <bit>

namespace forge::x86 {
    namespace {
        template <typename T> bool insertBounded(llvm::SmallVectorImpl<T> &values, T value) {
            auto pos = llvm::lower_bound(values, value);
            if (pos != values.end() && *pos == value) {
                return true;
            }

            if (values.size() == AddressFact::limit) {
                return false;
            }

            values.insert(pos, value);
            return true;
        }
    } // namespace

    AddressFact AddressFact::frameStack(uint64_t offset) {
        AddressFact result;
        result.displacement = offset;
        result.origin = FrameStack;
        result.unknown = false;
        return result;
    }

    std::optional<uint64_t> AddressFact::frameOffset() const {
        return origin == FrameStack ? std::optional(displacement) : std::nullopt;
    }

    AddressFact AddressFact::continuation(uint32_t callee) {
        AddressFact result;
        result.returns.push_back({callee, 0});
        result.unknown = false;
        return result;
    }

    AddressFact AddressFact::computed() const {
        if (origin == FrameStack) {
            return {};
        }

        auto result = *this;
        result.origin = Computed;
        return result;
    }

    AddressFact AddressFact::project(const AddressFact &entryRsps) const {
        if (origin == FrameStack) {
            return entryRsps.plus(AddressFact(displacement)).computed();
        }

        return computed();
    }

    void AddressFact::includeAddress(uint64_t va) {
        if (!unknown && !insertBounded(addresses, va)) {
            addresses.clear();
            unknown = true;
        }
    }

    void AddressFact::includeReturn(Continuation source) {
        if (!widenedReturns && !insertBounded(returns, source)) {
            returns.clear();
            addresses.clear();
            widenedReturns = true;
            unknown = true;
        }
    }

    AddressFact AddressFact::join(const AddressFact &other) const {
        if (*this == other) {
            return *this;
        }

        AddressFact result;
        result.unknown =
            unknown || other.unknown || origin == FrameStack || other.origin == FrameStack;
        result.widenedReturns = widenedReturns || other.widenedReturns;

        for (const auto *source : {this, &other}) {
            for (auto va : source->addresses) {
                result.includeAddress(va);
            }

            for (auto ret : source->returns) {
                result.includeReturn(ret);
            }
        }

        return result;
    }

    AddressFact AddressFact::addOffsets(const AddressFact &offsets) const {
        if (origin == FrameStack) {
            return offsets.origin == Constant ? frameStack(displacement + offsets.addresses.front())
                                              : AddressFact{};
        }

        AddressFact result;
        result.unknown = unknown;
        result.widenedReturns = widenedReturns;

        for (auto offset : offsets.addresses) {
            for (auto va : addresses) {
                result.includeAddress(va + offset);
            }

            for (auto ret : returns) {
                result.includeReturn({ret.callee, ret.offset + offset});
            }
        }

        if (!result.unknown && result.returns.empty()) {
            if (origin == Constant) {
                result.origin = offsets.origin;
            } else if (offsets.origin == Constant) {
                result.origin = origin;
            }
        }

        return result;
    }

    AddressFact AddressFact::plus(const AddressFact &other) const {
        if (other.known()) {
            return addOffsets(other);
        }

        if (known()) {
            return other.addOffsets(*this);
        }

        return {};
    }

    AddressFact AddressFact::times(uint64_t factor) const {
        if (factor == 1) {
            return *this;
        }

        if (!known()) {
            return {};
        }

        AddressFact result;
        result.unknown = false;
        for (auto value : addresses) {
            result.includeAddress(value * factor);
        }

        if (origin == Constant) {
            result.origin = Constant;
        }

        return result;
    }

    AddressFact AddressFact::masked(uint64_t mask) const {
        if (mask == UINT64_MAX) {
            return computed();
        }

        AddressFact result;
        result.unknown = false;

        if (known()) {
            for (auto value : addresses) {
                result.includeAddress(value & mask);
            }

            return result;
        }

        // An unconstrained input can produce all 2^popcount(mask) submasks.
        if (std::popcount(mask) >= static_cast<int>(std::bit_width(limit))) {
            return {};
        }

        auto submask = mask;
        for (;;) {
            result.includeAddress(submask);
            if (submask == 0) {
                return result;
            }

            submask = (submask - 1) & mask;
        }
    }

    const AddressFact *StackSpills::lookup(const Snapshot &slots, int64_t key) {
        if (!slots) {
            return nullptr;
        }

        const auto it = slots->find(key);
        return it == slots->end() ? nullptr : &it->second;
    }

    const AddressFact *StackSpills::find(uint64_t va) const {
        if (va - GuestMemory::base >= GuestMemory::capacity) {
            return nullptr;
        }

        return lookup(absolute, static_cast<int64_t>(va));
    }

    StackSpills::Slots &StackSpills::writable(Snapshot &slots) {
        if (!slots) {
            slots = std::make_shared<Slots>();
        } else if (slots.use_count() > 1) {
            slots = std::make_shared<Slots>(*slots);
        }

        return *slots;
    }

    bool StackSpills::mergeSlots(Snapshot &slots, const Snapshot &incoming) {
        if (slots == incoming) {
            return false;
        }

        // Record changes before detaching. An unchanged join of independently
        // constructed snapshots must leave shared storage and its borrows intact.
        const Slots empty;
        const auto &before = slots ? *slots : empty;
        const auto &after = incoming ? *incoming : empty;
        llvm::SmallVector<std::pair<int64_t, AddressFact>, 0> changes;
        for (const auto &[key, value] : before) {
            const auto *other = lookup(incoming, key);
            auto joined = value.join(other ? *other : AddressFact{});
            if (joined != value) {
                changes.emplace_back(key, std::move(joined));
            }
        }

        // A partial join has an unknown ordinary value, but the other edge can
        // still supply a genuine continuation that reaches a subsequent read.
        for (const auto &[key, value] : after) {
            if (before.contains(key)) {
                continue;
            }

            auto partial = AddressFact{}.join(value);
            if (partial.tracksSpill()) {
                changes.emplace_back(key, std::move(partial));
            }
        }

        if (changes.empty()) {
            return false;
        }

        auto &updated = writable(slots);
        for (auto &[key, value] : changes) {
            if (value.tracksSpill()) {
                updated.insert_or_assign(key, std::move(value));
            } else {
                updated.erase(key);
            }
        }

        if (updated.empty()) {
            slots.reset();
        }

        return true;
    }

    bool StackSpills::merge(const StackSpills &other) {
        const bool changed = mergeSlots(absolute, other.absolute);
        return mergeSlots(relative, other.relative) || changed;
    }

    AddressFact StackSpills::read(const AddressFact &address) const {
        if (const auto offset = address.frameOffset()) {
            const auto *saved = lookup(relative, std::bit_cast<int64_t>(*offset));
            return saved ? *saved : AddressFact{};
        }

        if (!address.known()) {
            return {};
        }

        std::optional<AddressFact> result;
        for (auto va : address.values()) {
            const auto *saved = find(va);
            const auto value = saved ? *saved : AddressFact{};
            result = result ? result->join(value) : value;
        }

        return result.value_or(AddressFact{});
    }

    void StackSpills::write(const AddressFact &address, unsigned width, const AddressFact &value) {
        const unsigned bytes = width / 8;
        if (const auto offset = address.frameOffset()) {
            // The slot and entry RSP must both fit the 4 KiB stack on a successful store.
            const auto key = std::bit_cast<int64_t>(*offset);
            constexpr int64_t capacity = GuestMemory::capacity;
            if (key <= -capacity || key >= capacity) {
                return;
            }

            absolute.reset();
            replace(relative, key, bytes, width == 64 ? value.computed() : AddressFact{});
            return;
        }

        if (!address.known()) {
            absolute.reset();
            relative.reset();
            return;
        }

        for (auto va : address.values()) {
            if (va - GuestMemory::base >= GuestMemory::capacity) {
                continue;
            }

            relative.reset();
            const bool exact = address.values().size() == 1 && width == 64 &&
                               va - GuestMemory::base <= GuestMemory::capacity - bytes;
            replace(absolute, static_cast<int64_t>(va), bytes,
                    exact ? value.computed() : AddressFact{});
        }
    }

    void StackSpills::replace(Snapshot &slots, int64_t key, unsigned bytes,
                              const AddressFact &saved) {
        if (slots) {
            const auto it = slots->lower_bound(key - 7);
            const bool overlaps = it != slots->end() && it->first < key + bytes;
            if (!overlaps && !saved.tracksSpill()) {
                return;
            }

            if (overlaps && it->first == key && it->second == saved &&
                std::next(it) == slots->lower_bound(key + bytes)) {
                return;
            }
        } else if (!saved.tracksSpill()) {
            return;
        }

        auto &updated = writable(slots);
        updated.erase(updated.lower_bound(key - 7), updated.lower_bound(key + bytes));
        if (saved.tracksSpill()) {
            updated.emplace(key, saved);
        } else if (updated.empty()) {
            slots.reset();
        }
    }
} // namespace forge::x86
