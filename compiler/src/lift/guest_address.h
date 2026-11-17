#pragma once

#include <cstdint>
#include <optional>

namespace forge {
    struct GuestAddress {
        uint64_t value;
    };

    // A nonempty span of guest bytes. Its last byte may be UINT64_MAX, so a
    // one-past-the-end address is not always representable.
    class GuestRange {
      public:
        static constexpr std::optional<GuestRange> fromOffset(GuestAddress base, uint64_t offset,
                                                              uint64_t size) {
            if (size == 0 || offset > UINT64_MAX - base.value) {
                return std::nullopt;
            }

            const GuestAddress start{base.value + offset};

            if (size - 1 > UINT64_MAX - start.value) {
                return std::nullopt;
            }

            return GuestRange(start, size);
        }

        constexpr bool contains(GuestAddress address) const {
            return address.value >= start.value && address.value - start.value < size;
        }

        constexpr bool overlaps(const GuestRange &other) const {
            return contains(other.start) || other.contains(start);
        }

      private:
        constexpr GuestRange(GuestAddress start, uint64_t size) : start(start), size(size) {}

        GuestAddress start;
        uint64_t size;
    };
} // namespace forge
