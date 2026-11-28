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

    AddressFact AddressFact::continuation(uint32_t callee) {
        AddressFact result;
        result.returns.push_back({callee, 0});
        result.unknown = false;
        return result;
    }

    AddressFact AddressFact::processStorage(uint64_t allocationSize) {
        AddressFact result;
        result.processOffset = 0;
        result.allocationSize = allocationSize;
        return result;
    }

    AddressFact AddressFact::computed() const {
        if (origin == FrameStack) {
            return {};
        }

        auto result = *this;
        result.origin = Computed;
        result.displacement.reset();
        return result;
    }

    AddressFact AddressFact::project(const AddressFact &entryRsps) const {
        if (origin == FrameStack) {
            return entryRsps.plus(AddressFact(*displacement)).computed();
        }

        return computed();
    }

    AddressFact AddressFact::reloaded(const AddressFact &entryRsps) const {
        auto result = project(entryRsps);
        result.displacement = displacement;
        return result;
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

        if (processOffset && processOffset == other.processOffset) {
            auto result = *this;
            result.allocationSize = std::min(allocationSize, other.allocationSize);
            return result;
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

    AddressFact AddressFact::joinInFrame(const AddressFact &other,
                                         const AddressFact &entryRsps) const {
        // Identical offsets still name the same slot across every caller. Mixed
        // alternatives (such as NULL and a local) need a common coordinate system.
        if ((displacement || other.displacement) && *this != other) {
            auto result = project(entryRsps).join(other.project(entryRsps));
            if (displacement == other.displacement) {
                result.displacement = displacement;
            }
            return result;
        }

        return join(other);
    }

    AddressFact AddressFact::addOffsets(const AddressFact &offsets) const {
        if (processOffset && offsets.addresses.size() == 1) {
            const auto delta = offsets.addresses.front();
            if (delta == 0) {
                return *this;
            }

            const auto offset = *processOffset + delta;
            const bool wrapped =
                delta <= INT64_MAX ? offset < *processOffset : offset > *processOffset;
            if (!wrapped && offset < allocationSize) {
                auto result = *this;
                result.processOffset = offset;
                return result;
            }
            return {};
        }

        if (origin == FrameStack) {
            return offsets.origin == Constant
                       ? frameStack(*displacement + offsets.addresses.front())
                       : AddressFact{};
        }

        AddressFact result;
        result.unknown = unknown;
        result.widenedReturns = widenedReturns;
        if (displacement && offsets.origin == Constant) {
            result.displacement = *displacement + offsets.addresses.front();
        } else if (origin == Constant && offsets.displacement) {
            result.displacement = addresses.front() + *offsets.displacement;
        }

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

    AddressFact StackSpills::Saved::read(unsigned bits, const AddressFact &entryRsps) const {
        if (bits > width) {
            return {};
        }

        return bits == 32 ? value.project(entryRsps).masked(UINT32_MAX) : value;
    }

    StackSpills::Saved StackSpills::Saved::join(const Saved &other,
                                                const AddressFact &entryRsps) const {
        if (width == other.width) {
            return {value.joinInFrame(other.value, entryRsps), width};
        }

        // A QWORD continuation on one path must survive an unknown high half on
        // another. Otherwise only the low DWORD is proved across these paths.
        const auto &wide = width == 64 ? value : other.value;
        auto partial = wide.join(AddressFact{});
        if (partial.tracksSpill()) {
            return {std::move(partial), 64};
        }

        return {read(32, entryRsps).join(other.read(32, entryRsps)), 32};
    }

    const StackSpills::Saved *StackSpills::lookup(const Snapshot &slots, int64_t key) {
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

        const auto *saved = lookup(absolute, static_cast<int64_t>(va));
        return saved && saved->width == 64 ? &saved->value : nullptr;
    }

    StackSpills::Slots &StackSpills::writable(Snapshot &slots) {
        if (!slots) {
            slots = std::make_shared<Slots>();
        } else if (slots.use_count() > 1) {
            slots = std::make_shared<Slots>(*slots);
        }

        return *slots;
    }

    bool StackSpills::mergeSlots(Snapshot &slots, const Snapshot &incoming,
                                 const AddressFact &entryRsps) {
        if (slots == incoming) {
            return false;
        }

        // Record changes before detaching. An unchanged join of independently
        // constructed snapshots must leave shared storage and its borrows intact.
        const Slots empty;
        const auto &before = slots ? *slots : empty;
        const auto &after = incoming ? *incoming : empty;
        llvm::SmallVector<std::pair<int64_t, Saved>, 0> changes;
        for (const auto &[key, value] : before) {
            const auto *other = lookup(incoming, key);
            auto joined = value.join(other ? *other : Saved{}, entryRsps);
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

            auto partial = Saved{}.join(value, entryRsps);
            if (partial.value.tracksSpill()) {
                changes.emplace_back(key, std::move(partial));
            }
        }

        if (changes.empty()) {
            return false;
        }

        auto &updated = writable(slots);
        for (auto &[key, value] : changes) {
            if (value.value.tracksSpill()) {
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

    bool StackSpills::merge(const StackSpills &other, const AddressFact &entryRsps) {
        const bool changed = mergeSlots(absolute, other.absolute, entryRsps);
        return mergeSlots(relative, other.relative, entryRsps) || changed;
    }

    AddressFact StackSpills::read(const AddressFact &address, const AddressFact &entryRsps,
                                  unsigned width) const {
        if (const auto offset = address.frameOffset()) {
            const auto *saved = lookup(relative, std::bit_cast<int64_t>(*offset));
            if (saved) {
                return saved->read(width, entryRsps);
            }
        }

        if (!address.known()) {
            return {};
        }

        std::optional<AddressFact> result;
        for (auto va : address.values()) {
            const auto *saved = lookup(absolute, std::bit_cast<int64_t>(va));
            const auto value = saved ? saved->read(width, entryRsps) : AddressFact{};
            result = result ? result->joinInFrame(value, entryRsps) : value;
        }

        return result.value_or(AddressFact{});
    }

    void StackSpills::write(const AddressFact &address, unsigned width, const AddressFact &value) {
        const unsigned bytes = width / 8;
        // Snapshots are local to one function activation. A saved frame offset
        // remains relative to that activation even if the slot itself has an absolute VA.
        const Saved saved = width == 32 || width == 64
                                ? Saved{value.frameOffset() ? value : value.computed(), width}
                                : Saved{};
        if (const auto offset = address.frameOffset()) {
            // The slot and entry RSP must both fit the 4 KiB stack on a successful store.
            const auto key = std::bit_cast<int64_t>(*offset);
            constexpr int64_t capacity = GuestMemory::capacity;
            if (key <= -capacity || key >= capacity) {
                return;
            }

            absolute.reset();
            replace(relative, key, bytes, saved);
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
            const bool exact = address.values().size() == 1 && bytes <= GuestMemory::capacity &&
                               va - GuestMemory::base <= GuestMemory::capacity - bytes;
            replace(absolute, static_cast<int64_t>(va), bytes, exact ? saved : Saved{});
        }
    }

    void StackSpills::replace(Snapshot &slots, int64_t key, unsigned bytes, const Saved &saved) {
        auto overlaps = [key](const auto &slot) {
            return slot.first + slot.second.width / 8 > key;
        };
        if (slots) {
            const auto end = slots->lower_bound(key + bytes);
            const auto it = std::find_if(slots->lower_bound(key - 7), end, overlaps);
            if (it == end && !saved.value.tracksSpill()) {
                return;
            }

            if (it != end && it->first == key && it->second == saved && std::next(it) == end) {
                return;
            }
        } else if (!saved.value.tracksSpill()) {
            return;
        }

        auto &updated = writable(slots);
        for (auto it = updated.lower_bound(key - 7);
             it != updated.end() && it->first < key + bytes;) {
            it = overlaps(*it) ? updated.erase(it) : std::next(it);
        }
        if (saved.value.tracksSpill()) {
            updated.emplace(key, saved);
        } else if (updated.empty()) {
            slots.reset();
        }
    }
} // namespace forge::x86
