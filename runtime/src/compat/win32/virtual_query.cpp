#include "../../core/instance.h"
#include "virtual_memory.h"

#include "forge/guest_range.h"

#include <array>
#include <bit>
#include <cstring>

namespace {
    using namespace forge::runtime;
    using namespace forge::runtime::win32;

    // MEMORY_BASIC_INFORMATION on Windows x64 has a two-byte PartitionId at 20,
    // two alignment bytes at 22, and four bytes of tail padding at 44.
    using QueryBytes = std::array<uint8_t, 48>;
    static_assert(sizeof(QueryBytes) == 48);

    template <size_t offset, typename T> void store(QueryBytes &bytes, T value) {
        static_assert(std::endian::native == std::endian::little);
        static_assert(offset + sizeof(T) <= sizeof(bytes));
        std::memcpy(bytes.data() + offset, &value, sizeof(value));
    }

    QueryBytes imageInformation(const ImageRegion &region) {
        QueryBytes bytes{};
        store<0>(bytes, region.base);
        store<8>(bytes, region.allocation);
        store<16>(bytes, uint32_t{0x80}); // SEC_IMAGE allocation protection.
        store<24>(bytes, region.size);
        store<32>(bytes,
                  region.state == ImageState::Committed ? uint32_t{0x1000} : uint32_t{0x2000});
        store<36>(bytes, windowsProtection(region.access));
        store<40>(bytes, uint32_t{0x1000000}); // MEM_IMAGE.
        return bytes;
    }

    forge_rt_status queryMemory(forge_rt_instance &owner, Thread &thread, uint64_t address,
                                forge::GuestAddress destination, uint64_t length, uint64_t &result,
                                forge_rt_memory_fault &fault) {
        const auto output = destination.value;
        ImageWrite probe;
        const auto fail = [&](uint32_t error) {
            // A later invalid page or query VA can follow successful write probes.
            // Recording their COW effect precedes either observable scalar result.
            probe.record();
            thread.lastError = error;
            result = 0;
            return FORGE_RT_OK;
        };

        if (length < sizeof(QueryBytes)) {
            return fail(badLength);
        }
        if (output < lowestUser || output % 8 || output > highestUser ||
            length - 1 > highestUser - output) {
            return fail(inaccessible);
        }

        forge_rt_memory_fault detail{};
        const auto checked = probeGuestWritePages(owner, thread, output, length, probe, detail);
        if (checked != FORGE_RT_OK) {
            if (checked != FORGE_RT_GUEST_FAULT || detail.reason == FORGE_RT_FAULT_STACK) {
                fault = detail;
                return checked;
            }
            if (unavailableQueryOutput(owner.reservations, detail.address)) {
                return FORGE_RT_UNSUPPORTED_MEMORY_QUERY;
            }
            return fail(inaccessible);
        }

        if (address > highestUser) {
            return fail(invalidParameter);
        }
        const auto region = queryImageRegion(owner.reservations, address, probe);
        // An embedder can reserve guest VAs that cannot hold a Windows user image.
        if (!region || region->allocation < lowestUser || region->allocationLast > highestUser) {
            return FORGE_RT_UNSUPPORTED_MEMORY_QUERY;
        }

        const auto bytes = imageInformation(*region);
        GuestWrite write{output, bytes.size(), bytes.data()};
        const auto ready = checkGuestWrite(owner, thread, write, detail);
        if (ready != FORGE_RT_OK) {
            if (ready == FORGE_RT_GUEST_FAULT && detail.reason != FORGE_RT_FAULT_STACK &&
                unavailableQueryOutput(owner.reservations, detail.address)) {
                return FORGE_RT_UNSUPPORTED_MEMORY_QUERY;
            }
            fault = detail;
            return ready;
        }

        // One interval includes the complete result and any additional probed image pages.
        // publishGuestWrite records it before transferring bytes or marking the stack.
        write.image = probe;
        publishGuestWrite(owner, write);
        result = bytes.size();
        return FORGE_RT_OK;
    }
} // namespace

extern "C" forge_rt_status forge_rt_virtual_query(forge_rt_instance *instance,
                                                  forge_rt_thread_token thread, uint64_t address,
                                                  uint64_t output, uint64_t length,
                                                  uint64_t *result,
                                                  forge_rt_memory_fault *fault) noexcept {
    if (!result || !fault) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return forge::runtime::withInstance(instance, [&](auto &owner) {
        const auto admitted = forge::runtime::checkPendingExecution(owner, thread);
        if (admitted != FORGE_RT_OK) {
            return admitted;
        }

        return queryMemory(owner, owner.threads.at(thread), address, {output}, length, *result,
                           *fault);
    });
}
