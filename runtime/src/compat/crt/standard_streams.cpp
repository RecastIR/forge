#include "standard_streams.h"

#include "../../core/instance.h"
#include "../process_state.h"
#include "forge/service_memory.h"

#include <algorithm>
#include <cerrno>
#include <cstring>

using namespace forge::runtime;
using namespace forge::win64;

forge_rt_status CrtStandardStreams::initialize(forge_rt_instance &instance,
                                               const StandardHandles &handles) {
    constexpr uint64_t lane = UINT64_C(1) << 44U;
    constexpr uint64_t stdinOffset = 256, stride = 8192;
    static_assert(sizeof(files) <= stdinOffset && stdinOffset + capacity <= stride);

    // Each placement has the same never-reused occurrence number. Relocating a PE
    // onto the preferred range must not give two occurrences the same FILE address.
    const auto token = issueToken();
    if (!token || token >= lane / stride) {
        return FORGE_RT_RESOURCE_EXHAUSTED;
    }

    for (size_t i = 0; i < files.size(); ++i) {
        files[i].flags = i == 0 ? 0x101 : 2;
        files[i].file = handles.streams[i].descriptor ? static_cast<int32_t>(i) : -2;
    }

    for (uint64_t window = lane; window < 8 * lane; window += lane) {
        const auto base = window + token * stride;
        files[0].ptr = files[0].base = base + stdinOffset;
        files[0].capacity = capacity;
        rows[0] = {base, sizeof(files), files.data(), FORGE_RT_READ, nullptr};
        rows[1] = {base + stdinOffset, capacity, stdinBytes.data(), FORGE_RT_READ, nullptr};
        mapping = {base, stdinOffset + capacity, rows.data(), rows.size()};
        const auto status = forge_rt_register_image(&instance, &mapping);
        if (status != FORGE_RT_MAPPING_CONFLICT) {
            return status;
        }
    }
    return FORGE_RT_MAPPING_CONFLICT;
}

forge_rt_status CrtStandardStreams::prepareBuffer(forge_rt_instance &instance, size_t index) {
    return withInstance(&instance, [&](auto &owner) {
        auto buffer = std::make_unique<Buffer>();
        const auto va = findGuestAllocation(owner.reservations, capacity, 16);
        if (!va) {
            return FORGE_RT_RESOURCE_EXHAUSTED;
        }

        buffer->row = {va, capacity, buffer->bytes.data(), FORGE_RT_READ, nullptr};
        buffer->mapping = {va, capacity, &buffer->row, 1};
        const auto status = publishOwnedImage(owner, buffer->mapping);
        if (status != FORGE_RT_OK) {
            return status;
        }

        buffers[index] = std::move(buffer);
        return FORGE_RT_OK;
    });
}

extern "C" forge_rt_status forge_rt_msvcrt_iob_func(forge_rt_instance *instance,
                                                    forge_rt_thread_token thread,
                                                    uint64_t *outBase) noexcept {
    if (!outBase) {
        return FORGE_RT_INVALID_ARGUMENT;
    }
    return withInstance(instance, [&](const auto &owner) {
        const auto status = checkPendingExecution(owner, thread);
        if (status != FORGE_RT_OK) {
            return status;
        }

        const auto &streams = owner.windows->streams;
        if (!streams) {
            return FORGE_RT_INVALID_STATE;
        }
        *outBase = streams->mapping.base;
        return FORGE_RT_OK;
    });
}

namespace {
    constexpr uint32_t streamError = 0x20;
    using Input = GuestBuffer<crtFwrite.arguments[0]>;

    struct Progress {
        size_t count;
        forge_rt_status status = FORGE_RT_OK;
        int error = 0;
        bool shortWrite = false;
        bool committed = false;
    };

    struct TextBlock {
        size_t source = 0;
        size_t physical = 0;
    };

    TextBlock encodeText(std::span<const uint8_t> bytes, std::span<uint8_t> output) {
        TextBlock block;
        for (const auto c : bytes) {
            if (c == '\n') {
                output[block.physical++] = '\r';
            }
            output[block.physical++] = c;
            ++block.source;
            if (block.physical >= output.size() - 1) {
                break;
            }
        }
        return block;
    }

    // The ANSI _write in the measured DLL starts a new OS transfer when the
    // converted staging area reaches 5119 bytes. A final LF can use byte 5120.
    template <class Reader>
    Progress writeText(const StandardStream &stream, bool hostSignals, uint64_t length,
                       Reader read) {
        if (!stream.descriptor) {
            return {0, FORGE_RT_OK, EBADF, true};
        }
        const auto &output = *stream.descriptor;
        if (!output.writable()) {
            return {0, FORGE_RT_OK, EACCES, true};
        }
        if (!output.outputSignalsSafe(hostSignals)) {
            return {0, FORGE_RT_HOST_CONFIGURATION};
        }

        constexpr size_t limit = 5119;
        std::array<uint8_t, limit> source;
        std::array<uint8_t, limit + 1> physical;
        uint64_t offset = 0;
        size_t accepted = 0, added = 0;
        while (offset < length) {
            auto bytes = std::span(source).first(std::min<uint64_t>(length - offset, limit));
            const auto status = read(offset, bytes);
            if (status != FORGE_RT_OK) {
                return {0, status};
            }

            const auto block = encodeText(bytes, physical);
            offset += block.source;
            added += block.physical - block.source;
            const auto written = output.writeSome(std::span(physical).first(block.physical));
            accepted += written.count;
            if (written.count != block.physical) {
                // _write subtracts all CR insertions staged in this call. A positive
                // OS prefix normally preserves errno. An underflow here cannot describe
                // an element count in the supported subset.
                if (accepted && accepted < added) {
                    return {0, FORGE_RT_UNSUPPORTED_CRT_STREAM, 0, true, true};
                }
                return {accepted ? accepted - added : 0, FORGE_RT_OK, written.error, true,
                        accepted != 0};
            }
        }
        return {static_cast<size_t>(length)};
    }

    Progress flushBuffer(CrtStandardStreams &streams, const StandardHandles &handles,
                         size_t index) {
        auto &file = streams.files[index];
        const size_t pending = file.ptr - file.base;
        if (!pending) {
            return {0};
        }

        const auto &buffer = streams.buffers[index]->bytes;
        const auto progress =
            writeText(handles.streams[index], handles.hostHandlesOutputSignals, pending,
                      [&](uint64_t offset, std::span<uint8_t> bytes) {
                          std::memcpy(bytes.data(), buffer.data() + offset, bytes.size());
                          return FORGE_RT_OK;
                      });
        if (progress.status == FORGE_RT_OK || progress.committed) {
            // Retire this attempted buffer even on an OS error. No prefix can be replayed.
            file.ptr = file.base;
            file.count = 0;
        }
        return progress;
    }

    forge_rt_status writeFailure(forge_rt_instance &instance, forge_rt_thread_token thread,
                                 LegacyFile &file, Progress progress) {
        uint32_t last = 0;
        int crt;
        switch (progress.error) {
        case 0:
        case EAGAIN:
            crt = 28;
            break;
        case EBADF:
            crt = 9;
            last = file.file == -2 ? 0 : 6;
            break;
        case EPIPE:
        case ECONNRESET:
            crt = 22;
            last = 232;
            break;
        case EACCES:
        case EPERM:
        case EROFS:
            crt = 9;
            last = 5;
            break;
        case EFBIG:
        case ENOSPC:
        case EDQUOT:
            crt = 28;
            last = 112;
            break;
        default:
            return FORGE_RT_UNSUPPORTED_CRT_STREAM;
        }

        file.flags |= streamError;
        if (!progress.committed) {
            instance.windows->crtErrno = crt;
        }
        return last ? forge_rt_set_last_error(&instance, thread, last) : FORGE_RT_OK;
    }

    forge_rt_status startBuffer(CrtStandardStreams &streams, WindowsProcessState &windows,
                                size_t index, const Input &input, uint64_t offset) {
        auto &file = streams.files[index];
        auto &buffer = *streams.buffers[index];
        const auto status = input.read(offset, std::span(buffer.bytes).first(1));
        if (status != FORGE_RT_OK) {
            return status;
        }

        if (!file.base) {
            file.base = buffer.mapping.base;
            file.capacity = CrtStandardStreams::capacity;
            file.flags |= 8U;
            if (file.file == -2) {
                windows.crtErrno = 9;
            }
        }

        // _flsbuf retains the new character even when draining the old buffer failed.
        file.ptr = file.base + 1;
        file.count = file.capacity - 1;
        return FORGE_RT_OK;
    }

    forge_rt_status rejectInputStream(ServiceInvocation &call, WindowsProcessState &windows,
                                      const StandardStream &stream, const Input &input) {
        if (input.byteSize() < CrtStandardStreams::capacity) {
            // _flsbuf receives the first source character even on an input-only stream.
            uint8_t first;
            const auto status = input.readScalar(0, first);
            if (status != FORGE_RT_OK) {
                return status;
            }
        } else if (stream.descriptor) {
            if (stream.descriptor->writable()) {
                return FORGE_RT_UNSUPPORTED_CRT_STREAM;
            }

            const auto status = input.validate();
            if (status != FORGE_RT_OK) {
                return status;
            }
            const auto error = forge_rt_set_last_error(call.instance, call.thread, 5);
            if (error != FORGE_RT_OK) {
                return error;
            }
        }

        windows.crtErrno = 9;
        windows.streams->files[0].flags |= streamError;
        return FORGE_RT_OK;
    }

    // Input is preflighted. The active invocation pins every mapping and descriptor
    // through these synchronous copies. Each OS write is made without the instance lock.
    forge_rt_status writeElements(forge_rt_instance &instance, forge_rt_thread_token thread,
                                  const StandardHandles &handles, size_t index, const Input &input,
                                  uint64_t width, uint64_t &elements) {
        auto &streams = *instance.windows->streams;
        auto &file = streams.files[index];
        constexpr auto block = CrtStandardStreams::capacity;
        // Acquire a required tail buffer before a direct prefix can reach the host.
        // Publish its FILE fields only when the guest operation reaches that tail.
        if (!streams.buffers[index] && input.byteSize() % block) {
            const auto status = streams.prepareBuffer(instance, index);
            if (status != FORGE_RT_OK) {
                return status;
            }
        }

        uint64_t done = 0;
        while (done < input.byteSize()) {
            const auto remaining = input.byteSize() - done;
            if (file.count > 0) {
                const auto n = std::min(remaining, static_cast<uint64_t>(file.count));
                auto bytes =
                    std::span(streams.buffers[index]->bytes).subspan(file.ptr - file.base, n);
                const auto status = input.read(done, bytes);
                if (status != FORGE_RT_OK) {
                    return status;
                }
                file.ptr += n;
                file.count -= static_cast<int32_t>(n);
                done += n;
                continue;
            }

            auto progress = flushBuffer(streams, handles, index);
            if (progress.status != FORGE_RT_OK) {
                return progress.status;
            }
            if (!progress.shortWrite && remaining >= block) {
                const auto length = remaining - remaining % block;
                progress = writeText(handles.streams[index], handles.hostHandlesOutputSignals,
                                     length, [&](uint64_t offset, std::span<uint8_t> bytes) {
                                         return input.read(done + offset, bytes);
                                     });
                done += progress.count;
            } else if (remaining < block) {
                const auto status = startBuffer(streams, *instance.windows, index, input, done);
                if (status != FORGE_RT_OK) {
                    return status;
                }
                done += !progress.shortWrite;
            }

            if (progress.status != FORGE_RT_OK) {
                return progress.status;
            }
            if (progress.shortWrite) {
                const auto status = writeFailure(instance, thread, file, progress);
                if (status != FORGE_RT_OK) {
                    return status;
                }
                break;
            }
        }

        elements = done / width;
        return FORGE_RT_OK;
    }
} // namespace

forge_rt_status CrtStandardStreams::finish(const StandardHandles &handles) noexcept {
    for (size_t i = 1; i < files.size(); ++i) {
        const auto progress = flushBuffer(*this, handles, i);
        if (progress.status != FORGE_RT_OK) {
            return progress.status;
        }
        if (progress.shortWrite) {
            files[i].flags |= streamError;
        }
    }
    return FORGE_RT_OK;
}

extern "C" forge_rt_status forge_rt_msvcrt_fwrite(forge_rt_instance *instance,
                                                  forge_rt_thread_token thread, uint64_t source,
                                                  uint64_t size, uint64_t count, uint64_t stream,
                                                  uint64_t *outElements,
                                                  forge_rt_memory_fault *fault) noexcept {
    if (!outElements || !fault) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    ServiceInvocation call{instance, thread, *fault};
    const auto status = withInstance(instance, [&](const auto &owner) {
        const auto live = checkPendingExecution(owner, thread);
        if (live == FORGE_RT_OK) {
            call.token = owner.threads.at(thread).invocation;
        }
        return live;
    });
    if (status != FORGE_RT_OK) {
        return status;
    }

    auto &windows = *instance->windows;
    if (!windows.streams || !windows.standardHandles) {
        return FORGE_RT_INVALID_STATE;
    }
    if (!size || !count) {
        *outElements = 0;
        return FORGE_RT_OK;
    }

    if (!stream) {
        windows.crtErrno = 22;
        *outElements = 0;
        return FORGE_RT_OK;
    }

    auto &streams = *windows.streams;
    const auto offset = stream - streams.mapping.base;
    if (offset >= sizeof(streams.files) || offset % sizeof(LegacyFile)) {
        return FORGE_RT_UNSUPPORTED_CRT_STREAM;
    }
    const auto input = guestBuffer<crtFwrite, 0>(call, std::tie(source, size, count, stream));
    if (!input || !source) {
        windows.crtErrno = 22;
        *outElements = 0;
        return FORGE_RT_OK;
    }
    const auto index = offset / sizeof(LegacyFile);
    if (!index) {
        const auto rejected =
            rejectInputStream(call, windows, windows.standardHandles->streams[0], *input);
        if (rejected == FORGE_RT_OK) {
            *outElements = 0;
        }
        return rejected;
    }

    const auto &descriptor = windows.standardHandles->streams[index].descriptor;
    if (descriptor && descriptor->kind() != darwin::StreamKind::RegularFile &&
        descriptor->kind() != darwin::StreamKind::Pipe) {
        return FORGE_RT_UNSUPPORTED_CRT_STREAM;
    }

    const auto checked = input->validate();
    if (checked != FORGE_RT_OK) {
        return checked;
    }

    // The verified subset uses a single signed-32-bit low-level transfer count.
    if (input->byteSize() > INT32_MAX) {
        return FORGE_RT_UNSUPPORTED_CRT_STREAM;
    }

    const auto &file = streams.files[index];
    const auto overlaps = [&](uint64_t va, uint64_t bytes) {
        return va <= source ? source - va < bytes : va - source < input->byteSize();
    };
    if (overlaps(stream, sizeof(LegacyFile)) ||
        (file.base && overlaps(file.base, CrtStandardStreams::capacity))) {
        return FORGE_RT_UNSUPPORTED_CRT_STREAM;
    }
    return writeElements(*instance, thread, *windows.standardHandles, index, *input, size,
                         *outElements);
}
