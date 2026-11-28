#include "standard_streams.h"

#include "format.h"

#include "../../core/instance.h"
#include "../process_state.h"
#include "../string_scan.h"

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
    if (buffers[index]) {
        return FORGE_RT_OK;
    }

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

    forge_rt_status admitOutput(ServiceInvocation &call, const StandardHandles *&handles) {
        return withInstance(call.instance, [&](const auto &owner) {
            const auto live = checkPendingExecution(owner, call.thread);
            if (live != FORGE_RT_OK) {
                return live;
            }

            if (!owner.windows->streams || !owner.windows->standardHandles) {
                return FORGE_RT_INVALID_STATE;
            }

            handles = &*owner.windows->standardHandles;
            call.token = owner.threads.at(call.thread).invocation;
            return FORGE_RT_OK;
        });
    }

    std::optional<size_t> streamIndex(const CrtStandardStreams &streams, uint64_t stream) {
        const uint64_t offset = stream - streams.mapping.base;
        if (offset >= sizeof(streams.files) || offset % sizeof(LegacyFile)) {
            return std::nullopt;
        }

        return offset / sizeof(LegacyFile);
    }

    bool supportedOutput(const StandardStream &stream) {
        return !stream.descriptor || stream.descriptor->kind() == darwin::StreamKind::RegularFile ||
               stream.descriptor->kind() == darwin::StreamKind::Pipe;
    }

    bool aliasesOutput(const CrtStandardStreams &streams, size_t index, uint64_t source,
                       uint64_t length) {
        const auto overlaps = [&](uint64_t va, uint64_t size) {
            return va <= source ? source - va < size : va - source < length;
        };
        const auto &buffer = streams.buffers[index];
        return length &&
               (overlaps(streams.mapping.base + index * sizeof(LegacyFile), sizeof(LegacyFile)) ||
                (buffer && overlaps(buffer->mapping.base, buffer->mapping.size)));
    }

    struct Progress {
        size_t accepted = 0;
        size_t inserted = 0;
        forge_rt_status status = FORGE_RT_OK;
        int error = 0;
        bool shortWrite = false;
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
            return {.error = EBADF, .shortWrite = true};
        }
        const auto &output = *stream.descriptor;
        if (!output.writable()) {
            return {.error = EACCES, .shortWrite = true};
        }
        if (!output.outputSignalsSafe(hostSignals)) {
            return {.status = FORGE_RT_HOST_CONFIGURATION};
        }

        constexpr size_t limit = 5119;
        std::array<uint8_t, limit> source;
        std::array<uint8_t, limit + 1> physical;
        uint64_t offset = 0;
        Progress progress;
        while (offset < length) {
            auto bytes = std::span(source).first(std::min<uint64_t>(length - offset, limit));
            const auto status = read(offset, bytes);
            if (status != FORGE_RT_OK) {
                progress.status = status;
                return progress;
            }

            const auto block = encodeText(bytes, physical);
            offset += block.source;
            progress.inserted += block.physical - block.source;
            const auto written = output.writeSome(std::span(physical).first(block.physical));
            progress.accepted += written.count;
            if (written.inspectionFailed) {
                progress.status =
                    written.error == EMFILE || written.error == ENFILE || written.error == ENOMEM
                        ? FORGE_RT_RESOURCE_EXHAUSTED
                        : FORGE_RT_HOST_CONFIGURATION;
                break;
            }
            if (written.count != block.physical) {
                progress.error = written.error;
                progress.shortWrite = true;
                break;
            }
        }
        return progress;
    }

    Progress flushBuffer(CrtStandardStreams &streams, const StandardHandles &handles,
                         size_t index) {
        auto &file = streams.files[index];
        const size_t pending = file.ptr - file.base;
        if (!pending) {
            return {};
        }

        const auto &buffer = streams.buffers[index]->bytes;
        const auto progress =
            writeText(handles.streams[index], handles.hostHandlesOutputSignals, pending,
                      [&](uint64_t offset, std::span<uint8_t> bytes) {
                          std::memcpy(bytes.data(), buffer.data() + offset, bytes.size());
                          return FORGE_RT_OK;
                      });
        if (progress.status == FORGE_RT_OK || progress.accepted) {
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
        if (!progress.accepted) {
            instance.windows->crtErrno = crt;
        }
        return last ? forge_rt_set_last_error(&instance, thread, last) : FORGE_RT_OK;
    }

    template <class Reader>
    forge_rt_status startBuffer(CrtStandardStreams &streams, WindowsProcessState &windows,
                                size_t index, const Reader &read, uint64_t offset) {
        auto &file = streams.files[index];
        auto &buffer = *streams.buffers[index];
        const auto status = read(offset, std::span(buffer.bytes).first(1));
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

    enum class WriteMode { Block, Character };

    // Input is preflighted. The active invocation pins every mapping and descriptor
    // through these synchronous copies. Each OS write is made without the instance lock.
    template <class Reader>
    forge_rt_status writeBytes(ServiceInvocation &call, const StandardHandles &handles,
                               size_t index, uint64_t length, const Reader &read,
                               uint64_t &accepted, WriteMode mode = WriteMode::Block) {
        auto &windows = *call.instance->windows;
        auto &streams = *windows.streams;
        auto &file = streams.files[index];
        constexpr auto block = CrtStandardStreams::capacity;

        uint64_t done = 0;
        while (done < length) {
            const auto remaining = length - done;
            if (file.count > 0) {
                const auto n = std::min(remaining, static_cast<uint64_t>(file.count));
                auto bytes =
                    std::span(streams.buffers[index]->bytes).subspan(file.ptr - file.base, n);
                const auto status = read(done, bytes);
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
            if (!progress.shortWrite && mode == WriteMode::Block && remaining >= block) {
                const auto direct = remaining - remaining % block;
                progress = writeText(handles.streams[index], handles.hostHandlesOutputSignals,
                                     direct, [&](uint64_t offset, std::span<uint8_t> bytes) {
                                         return read(done + offset, bytes);
                                     });
                if (progress.status != FORGE_RT_OK) {
                    return progress.status;
                }
                if (progress.accepted) {
                    // _write deducts every CR in the staged request, even on a short write.
                    if (progress.accepted < progress.inserted) {
                        return FORGE_RT_UNSUPPORTED_CRT_STREAM;
                    }
                    done += progress.accepted - progress.inserted;
                }
            } else if (mode == WriteMode::Character || remaining < block) {
                const auto status = startBuffer(streams, windows, index, read, done);
                if (status != FORGE_RT_OK) {
                    return status;
                }
                done += !progress.shortWrite;
            }

            if (progress.shortWrite) {
                const auto status = writeFailure(*call.instance, call.thread, file, progress);
                if (status != FORGE_RT_OK) {
                    return status;
                }
                break;
            }
        }

        accepted = done;
        return FORGE_RT_OK;
    }

    forge_rt_status writeFormatPart(ServiceInvocation &call, const StandardHandles &handles,
                                    size_t index, std::span<const char> source,
                                    FormattedOutput::Part part, int32_t &count) {
        const auto write = [&](std::span<const char> text, uint64_t &accepted) {
            return writeBytes(
                call, handles, index, text.size(),
                [&](uint64_t offset, auto bytes) {
                    std::memcpy(bytes.data(), text.data() + offset, bytes.size());
                    return FORGE_RT_OK;
                },
                accepted, WriteMode::Character);
        };

        while (!source.empty()) {
            uint64_t accepted;
            const auto status = write(source, accepted);
            if (status != FORGE_RT_OK) {
                return status;
            }

            if (accepted == source.size()) {
                count += static_cast<int32_t>(accepted);
                break;
            }

            count = -1;

            // The legacy string writer substitutes '?' only if errno is EILSEQ
            // after the failed character. Padding and literal writes have no retry.
            if (part != FormattedOutput::Part::Text || call.instance->windows->crtErrno != 42) {
                break;
            }

            source = source.subspan(accepted + 1);
            const auto replaced = write(std::span("?", 1), accepted);
            if (replaced != FORGE_RT_OK) {
                return replaced;
            }
            count += static_cast<int32_t>(accepted);
        }

        return FORGE_RT_OK;
    }

    forge_rt_status writeFormatted(ServiceInvocation &call, const StandardHandles &handles,
                                   size_t index, const FormattedOutput &output, int32_t &result) {
        if (output.length) {
            const auto status =
                call.instance->windows->streams->prepareBuffer(*call.instance, index);
            if (status != FORGE_RT_OK) {
                return status;
            }
        }

        int32_t count = 0;
        size_t begin = 0;
        for (const auto &write : std::span(output.writes).first(output.writeCount)) {
            const bool boundary = write.part == FormattedOutput::Part::Boundary;
            if (boundary && count < 0) {
                break;
            }

            const auto bytes = std::span(output.bytes).subspan(begin, write.end - begin);
            const auto status = writeFormatPart(call, handles, index, bytes, write.part, count);
            if (status != FORGE_RT_OK) {
                return status;
            }

            if (boundary && count < 0) {
                break;
            }
            begin = write.end;
        }

        result = count;
        return FORGE_RT_OK;
    }

    forge_rt_status writeLine(ServiceInvocation &call, const StandardHandles &handles,
                              uint64_t source, int32_t &result) {
        auto &windows = *call.instance->windows;
        if (!source) {
            windows.crtErrno = 22;
            result = -1;
            return FORGE_RT_OK;
        }

        constexpr size_t stdoutIndex = 1;
        if (!supportedOutput(handles.streams[stdoutIndex])) {
            return FORGE_RT_UNSUPPORTED_CRT_STREAM;
        }

        // _stbuf checks _isatty(_fileno(stdout)) before scanning, even with a live buffer.
        if (!handles.streams[stdoutIndex].descriptor) {
            windows.crtErrno = 9;
        }

        const auto string = guestBuffer<crtPuts, 0>(call, std::tie(source));
        uint64_t length;
        const auto scanned =
            scanString(string, crtPutsScanLimit, length, FORGE_RT_UNSUPPORTED_CRT_STREAM);
        if (scanned != FORGE_RT_OK) {
            return scanned;
        }

        auto &streams = *windows.streams;
        if (aliasesOutput(streams, stdoutIndex, source, length)) {
            return FORGE_RT_UNSUPPORTED_CRT_STREAM;
        }

        // Even an exact direct block needs a buffer for the following newline.
        const auto reserved = streams.prepareBuffer(*call.instance, stdoutIndex);
        if (reserved != FORGE_RT_OK) {
            return reserved;
        }

        uint64_t accepted;
        const auto payload = writeBytes(
            call, handles, stdoutIndex, length,
            [&](uint64_t offset, auto bytes) { return string.read(offset, bytes); }, accepted);
        if (payload != FORGE_RT_OK) {
            return payload;
        }
        if (accepted != length) {
            result = -1;
            return FORGE_RT_OK;
        }

        const auto newline = writeBytes(
            call, handles, stdoutIndex, 1,
            [](uint64_t, auto bytes) {
                bytes.front() = '\n';
                return FORGE_RT_OK;
            },
            accepted);
        if (newline == FORGE_RT_OK) {
            // Legacy Windows ignores the character writer's EOF after a complete payload.
            result = 0;
        }
        return newline;
    }
} // namespace

forge_rt_status CrtStandardStreams::finish(const StandardHandles &handles) noexcept {
    for (size_t i = 1; i < files.size(); ++i) {
        const auto progress = flushBuffer(*this, handles, i);
        if (progress.status != FORGE_RT_OK && !preserveAbortResult) {
            return progress.status;
        }

        if (progress.status != FORGE_RT_OK || progress.shortWrite) {
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
    const StandardHandles *handles = nullptr;
    const auto status = admitOutput(call, handles);
    if (status != FORGE_RT_OK) {
        return status;
    }

    auto &windows = *instance->windows;
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
    const auto selected = streamIndex(streams, stream);
    if (!selected) {
        return FORGE_RT_UNSUPPORTED_CRT_STREAM;
    }
    const auto input = guestBuffer<crtFwrite, 0>(call, std::tie(source, size, count, stream));
    if (!input || !source) {
        windows.crtErrno = 22;
        *outElements = 0;
        return FORGE_RT_OK;
    }
    const auto index = *selected;
    if (!index) {
        const auto rejected = rejectInputStream(call, windows, handles->streams[0], *input);
        if (rejected == FORGE_RT_OK) {
            *outElements = 0;
        }
        return rejected;
    }

    if (!supportedOutput(handles->streams[index])) {
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

    if (aliasesOutput(streams, index, source, input->byteSize())) {
        return FORGE_RT_UNSUPPORTED_CRT_STREAM;
    }

    if (input->byteSize() % CrtStandardStreams::capacity) {
        const auto reserved = streams.prepareBuffer(*instance, index);
        if (reserved != FORGE_RT_OK) {
            return reserved;
        }
    }

    uint64_t accepted;
    const auto written = writeBytes(
        call, *handles, index, input->byteSize(),
        [&](uint64_t offset, auto bytes) { return input->read(offset, bytes); }, accepted);
    if (written == FORGE_RT_OK) {
        *outElements = accepted / size;
    }
    return written;
}

extern "C" forge_rt_status forge_rt_msvcrt_puts(forge_rt_instance *instance,
                                                forge_rt_thread_token thread, uint64_t source,
                                                int32_t *outResult,
                                                forge_rt_memory_fault *fault) noexcept {
    if (!outResult || !fault) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    forge_rt_memory_fault detail{};
    ServiceInvocation call{instance, thread, detail};
    const StandardHandles *handles = nullptr;
    const auto admitted = admitOutput(call, handles);
    if (admitted != FORGE_RT_OK) {
        return admitted;
    }

    const auto status = writeLine(call, *handles, source, *outResult);
    if (status == FORGE_RT_GUEST_FAULT) {
        *fault = detail;
    }
    return status;
}

extern "C" forge_rt_status forge_rt_msvcrt_vfprintf(forge_rt_instance *instance,
                                                    forge_rt_thread_token thread, uint64_t stream,
                                                    uint64_t format, uint64_t arguments,
                                                    int32_t *outResult,
                                                    forge_rt_memory_fault *fault) noexcept {
    if (!outResult || !fault) {
        return FORGE_RT_INVALID_ARGUMENT;
    }

    forge_rt_memory_fault detail{};
    ServiceInvocation call{instance, thread, detail};
    const StandardHandles *handles = nullptr;
    const auto admitted = admitOutput(call, handles);

    if (admitted != FORGE_RT_OK) {
        return admitted;
    }

    auto &windows = *instance->windows;
    auto &streams = *windows.streams;
    const auto index = streamIndex(streams, stream);

    if (stream && !index) {
        return FORGE_RT_UNSUPPORTED_CRT_STREAM;
    }

    if (!index || !format) {
        windows.crtErrno = 22;
        *outResult = -1;
        return FORGE_RT_OK;
    }

    if (!*index || !supportedOutput(handles->streams[*index])) {
        return FORGE_RT_UNSUPPORTED_CRT_STREAM;
    }

    // _stbuf checks the descriptor before _output reads the format or any operand.
    if (!handles->streams[*index].descriptor) {
        windows.crtErrno = 9;
    }

    const auto parameters = std::tie(stream, format, arguments);
    FormattedOutput output;
    const auto status = formatOutput(guestBuffer<crtVfprintf, 1>(call, parameters),
                                     guestBuffer<crtVfprintf, 2>(call, parameters), output);

    if (status != FORGE_RT_OK) {
        if (status == FORGE_RT_GUEST_FAULT) {
            *fault = detail;
        }

        return status;
    }

    const auto overlaps = [&](const FormattedOutput::StringRead &input) {
        return aliasesOutput(streams, *index, input.address, input.size);
    };

    if (aliasesOutput(streams, *index, format, output.formatBytes) ||
        aliasesOutput(streams, *index, arguments, output.slotBytes) ||
        std::ranges::any_of(std::span(output.strings).first(output.stringCount), overlaps)) {
        return FORGE_RT_UNSUPPORTED_CRT_STREAM;
    }

    return writeFormatted(call, *handles, *index, output, *outResult);
}
