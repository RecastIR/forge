#include "../../core/instance.h"
#include "virtual_memory.h"

#include <bit>

namespace {
    using namespace forge::runtime::win32;
    constexpr uint32_t guard = 0x100, noCache = 0x200, writeCombine = 0x400;
    constexpr uint32_t enclaveUnvalidated = 0x20000000, targetsNoUpdate = 0x40000000,
                       enclaveThreadControl = 0x80000000;

    bool invalidProtection(uint32_t flags) {
        const auto base = flags & 0xffU;
        const auto modifiers = flags & (guard | noCache | writeCombine);
        return !std::has_single_bit(base) || (modifiers && base == noAccess) ||
               std::popcount(modifiers) > 1;
    }

    forge_rt_status probeOutput(forge_rt_instance &owner, const forge::runtime::Thread &active,
                                forge::runtime::GuestWrite &out, forge_rt_memory_fault &fault) {
        if (out.address < lowestUser || out.address > highestUser - (out.size - 1)) {
            fault = {out.address, FORGE_RT_WRITE, FORGE_RT_FAULT_UNMAPPED};
            return FORGE_RT_GUEST_FAULT;
        }

        const auto status = checkGuestWrite(owner, active, out, fault);
        if (status == FORGE_RT_GUEST_FAULT && fault.reason != FORGE_RT_FAULT_STACK &&
            unavailableProtectionOutput(owner.reservations, fault.address)) {
            return FORGE_RT_UNSUPPORTED_PAGE_PROTECTION;
        }

        return status;
    }

    forge_rt_status changePages(forge_rt_instance &owner, forge::runtime::Thread &active,
                                uint64_t address, uint64_t size, uint32_t protection,
                                uint64_t output, int32_t &result, forge_rt_memory_fault &fault) {
        using namespace forge::runtime;
        const auto fail = [&](uint32_t error) {
            active.lastError = error;
            result = 0;
            return FORGE_RT_OK;
        };

        if (invalidProtection(protection)) {
            return fail(invalidParameter);
        }

        forge_rt_memory_fault outputFault{};
        GuestWrite out{output, sizeof(uint32_t), nullptr};
        const auto checked = probeOutput(owner, active, out, outputFault);
        if (checked == FORGE_RT_GUEST_FAULT) {
            if (outputFault.reason == FORGE_RT_FAULT_STACK) {
                fault = outputFault;
                return checked;
            }

            return fail(inaccessible);
        }

        if (checked != FORGE_RT_OK) {
            return checked;
        }

        // Windows probes a valid protection mask and the output before checking zero size.
        if (!size) {
            // The Windows write probe realizes a pristine output page even though the
            // zero-length call preserves the DWORD and subsequently fails.
            out.image.record();
            return fail(invalidParameter);
        }

        if (address > highestUser || size - 1 > highestUser - address) {
            return fail(invalidParameter);
        }

        constexpr uint64_t mask = FORGE_RT_GUEST_PAGE_SIZE - 1;
        const PageInterval pages{address & ~mask, (address + (size - 1)) | mask};
        const PageInterval outBytes{output, output + sizeof(uint32_t) - 1};
        ProtectionUpdate update;
        const auto status = address < lowestUser ? ProtectionResult::Unmapped
                                                 : queryProtection(owner.reservations, address,
                                                                   pages, outBytes, update);
        // The enclave-unvalidated bit is ignored on an ordinary image data page
        // for this measured read-only request.
        const bool requestsReadOnly =
            protection == readOnly || protection == (enclaveUnvalidated | readOnly);
        uint32_t error = 0;
        if (status == ProtectionResult::Unmapped || status == ProtectionResult::CrossReservation) {
            error = invalidAddress;
        } else if (update.owner && ((protection & (noCache | writeCombine)) ||
                                    ((protection & targetsNoUpdate) && !(protection & 0xf0)) ||
                                    protection == (enclaveThreadControl | readOnly))) {
            error = invalidParameter;
        } else if (status != ProtectionResult::Supported ||
                   (!requestsReadOnly && protection != readWrite)) {
            return FORGE_RT_UNSUPPORTED_PAGE_PROTECTION;
        }

        // After successful argument probing, NT publishes PAGE_NOACCESS for a range
        // rejection. This output side effect is observable even though BOOL is false.
        if (!error) {
            update.stage(pages, protection == readWrite);
        }

        const auto old = error ? noAccess : windowsProtection(update.previous);
        const bool losesOutput = !error && requestsReadOnly && outBytes.first <= pages.last &&
                                 outBytes.last >= pages.first;
        out.source = losesOutput ? nullptr : &old;
        publishGuestWrite(owner, out);

        if (error) {
            return fail(error);
        }

        // NT can successfully protect its own output: the later DWORD store is then
        // inaccessible and leaves the guest bytes untouched. No partial store is visible.
        update.commit();
        result = 1;
        return FORGE_RT_OK;
    }
} // namespace

extern "C" forge_rt_status forge_rt_virtual_protect(forge_rt_instance *instance,
                                                    forge_rt_thread_token thread, uint64_t address,
                                                    uint64_t size, uint32_t protection,
                                                    uint64_t oldProtection, int32_t *result,
                                                    forge_rt_memory_fault *fault) noexcept {
    if (!result || !fault) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return forge::runtime::withInstance(instance, [&](auto &owner) {
        const auto admission = forge::runtime::checkPendingExecution(owner, thread);
        if (admission != FORGE_RT_OK) {
            return admission;
        }

        return changePages(owner, owner.threads.at(thread), address, size, protection,
                           oldProtection, *result, *fault);
    });
}
