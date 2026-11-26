#include "instance.h"
#include "page_protection.h"

#include "forge/guest_range.h"
#include "forge/process.h"

#include <algorithm>
#include <cstring>
#include <span>

// The lifetime race target pauses a test-only build at the last possible point
// before transfer. The shipped archive contains neither the probe nor a branch.
#ifdef FORGE_RUNTIME_TEST_TRANSFER
void forgeMemoryTransferProbe() noexcept;
#endif

using namespace forge;
using namespace forge::runtime;

namespace {
    struct Segment {
        const uint8_t *bytes;
        size_t size;
        uint32_t permissions;
        const Thread *stackOwner;
        uint8_t *marks;
        PageProtections *protections = nullptr;
    };

    // Locate the first reservation and row with two binary searches. Copies of this cursor
    // walk the same approved rows during preflight and transfer under the instance lock.
    class Cursor {
      public:
        Cursor(const std::vector<Reservation> &reservations, uint64_t address)
            : reservation(std::ranges::upper_bound(reservations, address, {}, &Reservation::base)),
              end(reservations.end()) {
            if (reservation == reservations.begin()) {
                return;
            }

            --reservation;

            if (const auto *image = reservation->image; image && image->count != 0) {
                const std::span rows(image->regions, static_cast<size_t>(image->count));
                const auto after =
                    std::ranges::upper_bound(rows, address, {}, &forge_rt_image_region::start);

                if (after != rows.begin()) {
                    rowIndex = static_cast<size_t>(after - rows.begin() - 1);
                }
            }
        }

        Segment next(uint64_t address, uint64_t remaining) {
            if (reservation == end || address < reservation->base ||
                address - reservation->base >= reservation->size) {
                return {};
            }

            Segment segment{};

            if (const auto *owner = reservation->stackOwner) {
                const auto offset = address - owner->stack.base;
                segment = {static_cast<const uint8_t *>(owner->stack.bytes) + offset,
                           static_cast<size_t>(std::min(remaining, owner->stack.size - offset)),
                           FORGE_RT_READ | FORGE_RT_WRITE, owner, owner->stack.marks + offset};
            } else {
                const auto &image = *reservation->image;

                if (rowIndex == image.count) {
                    return {};
                }

                const auto &row = image.regions[rowIndex];

                if (address < row.start || address - row.start >= row.size) {
                    return {};
                }

                const auto offset = address - row.start;
                segment = {static_cast<const uint8_t *>(row.bytes) + offset,
                           static_cast<size_t>(std::min(remaining, row.size - offset)),
                           row.permissions,
                           nullptr,
                           nullptr,
                           reservation->protections};
                ++rowIndex;
            }

            if (segment.size == reservation->size - (address - reservation->base)) {
                ++reservation;
                rowIndex = 0;
            }

            return segment;
        }

      private:
        std::vector<Reservation>::const_iterator reservation;
        std::vector<Reservation>::const_iterator end;
        size_t rowIndex = 0;
    };

    forge_rt_status report(forge_rt_memory_fault &fault, uint64_t address, uint32_t access,
                           uint32_t reason) {
        fault = {address, access, reason};
        return FORGE_RT_GUEST_FAULT;
    }

    forge_rt_status checkStack(const Segment &segment, uint64_t address, uint32_t access,
                               const Thread &active, forge_rt_memory_fault &fault, bool readSaved) {
        // Generated frame code may be modifying another activation's marks without taking
        // the instance mutex. Only its innermost synchronous owner can examine them.
        if (segment.stackOwner != &active || executingInvocation != active.invocation) {
            return report(fault, address, access, FORGE_RT_FAULT_STACK);
        }

        const bool read = (access & FORGE_RT_READ) != 0;
        const bool write = (access & FORGE_RT_WRITE) != 0;
        const bool callback = callbackInvocation == active.invocation;
        auto limit = segment.size;
        const auto endOffset = address - active.stack.base + segment.size;

        if (callback && endOffset > FORGE_RT_INITIALIZER_HOME_END) {
            // The lowest active callback frame has the tightest bound. Only a mark in
            // this prefix could exclude any requested byte. The managed stack is 4 KiB.
            const auto *slot = static_cast<const uint8_t *>(
                std::memchr(active.stack.marks, FORGE_RT_MARK_CALLBACK_RETURN,
                            endOffset - FORGE_RT_INITIALIZER_HOME_END));

            if (slot) {
                const auto offset = static_cast<size_t>(slot - active.stack.marks);
                const auto end = active.stack.base + offset + FORGE_RT_INITIALIZER_HOME_END;
                limit = end > address ? static_cast<size_t>(end - address) : 0;
            }
        }

        for (size_t i = 0; i < limit; ++i) {
            const auto va = address + i;
            const auto mark = segment.marks[i];
            const bool outer = va >= active.stack.outerReturn && va - active.stack.outerReturn < 8;

            if (callback && mark == FORGE_RT_MARK_CALLBACK_RETURN) {
                return FORGE_RT_UNSUPPORTED_CALLBACK_RETURN;
            }

            const bool readable =
                readSaved ? mark != FORGE_RT_MARK_UNINITIALIZED
                          : mark == FORGE_RT_MARK_CONCRETE || mark == FORGE_RT_MARK_RETURN;

            if (outer || (write && mark == FORGE_RT_MARK_RETURN) || (read && !readable)) {
                return report(fault, va, access, FORGE_RT_FAULT_STACK);
            }
        }

        return limit == segment.size ? FORGE_RT_OK : FORGE_RT_UNSUPPORTED_CALLBACK_ARGUMENT;
    }

    forge_rt_status preflight(Cursor cursor, const Thread &active, uint64_t start, uint64_t count,
                              uint32_t access, forge_rt_memory_fault &fault, bool readSaved) {
        uint64_t offset = 0;

        while (offset < count) {
            const auto address = start + offset;
            const auto segment = cursor.next(address, count - offset);

            if (!segment.size) {
                return report(fault, address, access, FORGE_RT_FAULT_UNMAPPED);
            }

            if ((segment.permissions & access) != access) {
                return report(fault, address, access, FORGE_RT_FAULT_PERMISSION);
            }

            if ((access & FORGE_RT_WRITE) && segment.protections) {
                if (const auto denied =
                        segment.protections->deniedWrite({address, address + (segment.size - 1)})) {
                    return report(fault, *denied, access, FORGE_RT_FAULT_PERMISSION);
                }
            }

            if (segment.stackOwner) {
                const auto status = checkStack(segment, address, access, active, fault, readSaved);

                if (status != FORGE_RT_OK) {
                    return status;
                }
            }

            offset += segment.size;
        }

        return FORGE_RT_OK;
    }

    // Only the managed PE has mutable protection state. One contiguous checked copy
    // intersects that reservation at most once, even when it visits several rows.
    void recordGuestWrite(Cursor cursor, uint64_t start, uint64_t count) {
        PageProtections *owner = nullptr;
        PageInterval bytes{};
        uint64_t offset = 0;
        while (offset < count) {
            const auto address = start + offset;
            const auto segment = cursor.next(address, count - offset);
            if (segment.protections) {
                if (!owner) {
                    owner = segment.protections;
                    bytes.first = address;
                }
                bytes.last = address + (segment.size - 1);
            }
            offset += segment.size;
        }
        if (owner) {
            owner->recordWrite(bytes);
        }
    }

    struct HostBuffers {
        uint8_t *destination = nullptr;
        const uint8_t *source = nullptr;
    };

    void transfer(Cursor cursor, uint64_t start, uint64_t count, HostBuffers host) {
        size_t offset = 0;

        while (offset < count) {
            const auto segment = cursor.next(start + offset, count - offset);

            if (host.destination) {
                std::memcpy(host.destination + offset, segment.bytes, segment.size);
            } else {
                // The WRITE permission was validated for every row. The backing owner
                // supplies writable native storage for exactly these rows.
                std::memcpy(const_cast<uint8_t *>(segment.bytes), host.source + offset,
                            segment.size);
            }

            if (host.source && segment.marks) {
                std::memset(segment.marks, FORGE_RT_MARK_CONCRETE, segment.size);
            }

            offset += segment.size;
        }
    }

    forge_rt_status accessGuest(forge_rt_instance *instance, forge_rt_thread_token thread,
                                forge_rt_invocation_token invocation, uint64_t address,
                                uint64_t count, uint32_t access, HostBuffers host,
                                forge_rt_memory_fault *fault, bool readSaved = false) noexcept {
        if (!fault || !access || (access & ~(FORGE_RT_READ | FORGE_RT_WRITE)) != 0) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        return withInstance(instance, [&](const auto &process) {
            const auto entry = process.threads.find(thread);

            if (entry == process.threads.end()) {
                return FORGE_RT_INVALID_THREAD;
            }

            if (!invocation || entry->second.invocation != invocation ||
                (process.managedExecution && executingInvocation != invocation)) {
                return FORGE_RT_INVALID_INVOCATION;
            }

            if (!count) {
                return FORGE_RT_OK;
            }

            if (!GuestRange::fromOffset({address}, 0, count)) {
                return report(*fault, address, access, FORGE_RT_FAULT_OVERFLOW);
            }

            const Cursor cursor(process.reservations, address);
            const auto status =
                preflight(cursor, entry->second, address, count, access, *fault, readSaved);

            if (status == FORGE_RT_OK && (host.source || host.destination)) {
#ifdef FORGE_RUNTIME_TEST_TRANSFER
                forgeMemoryTransferProbe();
#endif
                if (host.source && process.managedExecution) {
                    recordGuestWrite(cursor, address, count);
                }
                transfer(cursor, address, count, host);
            }

            return status;
        });
    }
} // namespace

forge_rt_status forge::runtime::checkProtectionOutput(const forge_rt_instance &instance,
                                                      const Thread &active, uint64_t address,
                                                      forge_rt_memory_fault &fault) {
    if (!GuestRange::fromOffset({address}, 0, sizeof(uint32_t))) {
        return report(fault, address, FORGE_RT_WRITE, FORGE_RT_FAULT_OVERFLOW);
    }

    return preflight(Cursor(instance.reservations, address), active, address, sizeof(uint32_t),
                     FORGE_RT_WRITE, fault, false);
}

void forge::runtime::publishProtectionOutput(const forge_rt_instance &instance, uint64_t address,
                                             const uint32_t *value) {
    Cursor cursor(instance.reservations, address);
    recordGuestWrite(cursor, address, sizeof(uint32_t));
    if (value) {
        transfer(cursor, address, sizeof(*value),
                 {nullptr, reinterpret_cast<const uint8_t *>(value)});
    }
}

extern "C" void *forge_rt_resolve_process_scalar(forge_rt_execution *execution, uint64_t address,
                                                 uint32_t size, uint32_t access) noexcept {
    if (!execution) {
        return nullptr;
    }

    const auto permissions = access == FORGE_RT_SCALAR_READ_SAVED ? FORGE_RT_READ : access;
    const uint8_t *bytes = nullptr;
    const auto status = withInstance(execution->instance, [&](const auto &instance) {
        if (!size || size > sizeof(uint64_t) || !permissions ||
            (permissions & ~(FORGE_RT_READ | FORGE_RT_WRITE))) {
            return FORGE_RT_INVALID_ARGUMENT;
        }

        if (instance.managedExecution != execution) {
            return FORGE_RT_INVALID_STATE;
        }

        const auto active = instance.threads.find(execution->thread);

        if (!executingInvocation || active == instance.threads.end() ||
            active->second.invocation != executingInvocation) {
            return FORGE_RT_INVALID_INVOCATION;
        }

        const auto segment = Cursor(instance.reservations, address).next(address, size);

        if (!segment.stackOwner && segment.size == size &&
            (segment.permissions & permissions) == permissions &&
            (!(permissions & FORGE_RT_WRITE) || !segment.protections ||
             !segment.protections->deniedWrite({address, address + (size - 1)}))) {
            if ((permissions & FORGE_RT_WRITE) && segment.protections) {
                segment.protections->recordWrite({address, address + (size - 1)});
            }
            bytes = segment.bytes;
        }

        return FORGE_RT_OK;
    });

    if (status != FORGE_RT_OK) {
        execution->result = {FORGE_RT_RUNTIME_FAILURE, status, 0, {}, 0};
    } else if (!bytes) {
        forge_rt_report_scalar_boundary(execution, address, size, access, 0);
    }

    // Registration and process admission pin all published backing through the instruction.
    // A mutable pointer is usable only after the requested write permission was checked.
    return const_cast<uint8_t *>(bytes);
}

extern "C" void forge_rt_report_scalar_boundary(forge_rt_execution *execution, uint64_t address,
                                                uint32_t size, uint32_t access,
                                                uint32_t stack) noexcept {
    if (!execution) {
        return;
    }

    if (!size || size > sizeof(uint64_t) || stack > 1) {
        execution->result = {FORGE_RT_RUNTIME_FAILURE, FORGE_RT_INVALID_ARGUMENT, 0, {}, 0};
        return;
    }

    const bool readSaved = access == FORGE_RT_SCALAR_READ_SAVED;
    const auto permissions = readSaved ? FORGE_RT_READ : access;
    uint64_t count = size;

    if (stack) {
        // Stay in the stack domain even if another mapping abuts its end.
        const auto offset = address - FORGE_RT_STACK_BASE;
        count = offset < FORGE_RT_STACK_SIZE ? std::min(count, FORGE_RT_STACK_SIZE - offset) : 0;
    }

    forge_rt_memory_fault fault{};
    auto status = accessGuest(execution->instance, execution->thread, executingInvocation, address,
                              count, permissions, {}, &fault, readSaved);

    if (status == FORGE_RT_OK && count < size) {
        status = report(fault, address + count, permissions, FORGE_RT_FAULT_STACK);
    }

    if (status == FORGE_RT_GUEST_FAULT) {
        execution->result = {FORGE_RT_EXECUTION_FAULT, status, 0, fault, FORGE_RT_FAULT_MEMORY};
    } else if (status == FORGE_RT_UNSUPPORTED_CALLBACK_RETURN ||
               status == FORGE_RT_UNSUPPORTED_CALLBACK_ARGUMENT) {
        execution->result = {FORGE_RT_UNSUPPORTED, status, 0, {}, 0};
    } else if (status == FORGE_RT_OK && !stack) {
        // All bytes were accessible, but one scalar cannot span native rows.
        execution->result = {FORGE_RT_UNSUPPORTED, FORGE_RT_OK, 0, {}, 0};
    } else {
        const auto failure = status == FORGE_RT_OK ? FORGE_RT_INTERNAL_ERROR : status;
        execution->result = {FORGE_RT_RUNTIME_FAILURE, failure, 0, {}, 0};
    }
}

extern "C" forge_rt_status
forge_rt_validate_guest(forge_rt_instance *instance, forge_rt_thread_token thread,
                        forge_rt_invocation_token invocation, uint64_t address, uint64_t count,
                        uint32_t access, forge_rt_memory_fault *fault) noexcept {
    return accessGuest(instance, thread, invocation, address, count, access, {}, fault);
}

extern "C" forge_rt_status
forge_rt_read_guest(forge_rt_instance *instance, forge_rt_thread_token thread,
                    forge_rt_invocation_token invocation, uint64_t address, uint64_t count,
                    void *buffer, size_t capacity, forge_rt_memory_fault *fault) noexcept {
    if (count > capacity || (count && !buffer)) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return accessGuest(instance, thread, invocation, address, count, FORGE_RT_READ,
                       {static_cast<uint8_t *>(buffer), nullptr}, fault);
}

extern "C" forge_rt_status
forge_rt_write_guest(forge_rt_instance *instance, forge_rt_thread_token thread,
                     forge_rt_invocation_token invocation, uint64_t address, uint64_t count,
                     const void *buffer, size_t capacity, forge_rt_memory_fault *fault) noexcept {
    if (count > capacity || (count && !buffer)) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    return accessGuest(instance, thread, invocation, address, count, FORGE_RT_WRITE,
                       {nullptr, static_cast<const uint8_t *>(buffer)}, fault);
}
