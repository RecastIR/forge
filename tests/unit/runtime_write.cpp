#include "../../runtime/src/platform/darwin/io.h"
#include <forge/process.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <optional>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {
    void require(bool value, const char *expression, int line) {
        if (!value) {
            std::fprintf(stderr, "runtime_write.cpp:%d: %s\n", line, expression);
            std::abort();
        }
    }

#define REQUIRE(...) require((__VA_ARGS__), #__VA_ARGS__, __LINE__)

    struct Attempt {
        int count;
        int error;
    };

    void checkWrites(std::span<const Attempt> attempts, size_t expected, int expectedError) {
        constexpr std::array<uint8_t, 5> source{0, 0xff, 0x41, 0, 0x0a};
        std::vector<uint8_t> observed;
        size_t call = 0;
        const auto progress =
            forge::runtime::darwin::writeAll(source, [&](std::span<const uint8_t> remaining) {
                if (call >= attempts.size() ||
                    remaining.size() != source.size() - observed.size()) {
                    std::abort();
                }

                const auto attempt = attempts[call++];

                if (attempt.count > 0) {
                    const auto consumed = remaining.first(static_cast<size_t>(attempt.count));
                    observed.insert(observed.end(), consumed.begin(), consumed.end());
                }

                errno = attempt.error;
                return attempt.count;
            });

        if (call != attempts.size() || progress.count != expected ||
            progress.error != expectedError || observed.size() != expected ||
            !std::ranges::equal(observed, std::span(source).first(expected))) {
            std::fputs("standard output acknowledged an incorrect byte count or sequence\n",
                       stderr);
            std::abort();
        }
    }

    void checkDescriptorOwnership() {
        using namespace forge::runtime::darwin;
        int ends[2];
        REQUIRE(pipe(ends) == 0);
        std::optional<Descriptor> owner;

        {
            std::optional<Descriptor> captured;
            const auto result = Descriptor::capture(ends[1], captured);
            REQUIRE(result.status == CaptureResult::Status::Captured && result.error == 0);
            REQUIRE(captured && captured->kind() == StreamKind::Pipe &&
                    captured->accessMode() == O_WRONLY);
            owner.emplace(std::move(*captured));
        }

        const auto missing = Descriptor::capture(-1, owner);
        REQUIRE(missing.status == CaptureResult::Status::Unavailable && missing.error == EBADF);
        const int copy = owner->get();
        REQUIRE(copy >= 3 && copy != ends[1]);
        REQUIRE(fcntl(copy, F_GETFD) == FD_CLOEXEC);
        owner.reset();
        REQUIRE(fcntl(copy, F_GETFD) == -1 && errno == EBADF);
        char byte;
        REQUIRE(write(ends[1], "H", 1) == 1 && read(ends[0], &byte, 1) == 1 && byte == 'H');
        REQUIRE(close(ends[1]) == 0 && close(ends[0]) == 0);
    }

    constexpr uint64_t sourceAddress = 0x2000;
    constexpr uint32_t requestLength = PIPE_BUF * 2;

    void writePartial(forge_rt_execution *execution) {
        auto *instance = execution->instance;
        const auto thread = execution->thread;
        uint64_t handle = 0;
        forge_rt_invocation_token token;
        REQUIRE(forge_rt_current_invocation(instance, thread, &token) == FORGE_RT_OK);
        REQUIRE(forge_rt_get_std_handle(instance, thread, 0xfffffff5, &handle) == FORGE_RT_OK);

        constexpr auto countAddress = FORGE_RT_ENTRY_RSP - 8;
        int32_t success = -1;
        forge_rt_memory_fault fault{};
        REQUIRE(forge_rt_write_file(instance, thread, handle, sourceAddress, requestLength,
                                    countAddress, 0, &success, &fault) == FORGE_RT_OK);
        REQUIRE(success == 0);
        uint32_t count = 0, error = 0;
        REQUIRE(forge_rt_get_last_error(instance, thread, &error) == FORGE_RT_OK);
        REQUIRE(error == 1237); // ERROR_RETRY for a nonblocking pipe with no remaining room.
        REQUIRE(forge_rt_read_guest(instance, thread, token, countAddress, sizeof(count), &count,
                                    sizeof(count), &fault) == FORGE_RT_OK);
        REQUIRE(count == PIPE_BUF);
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, count, {}, 0};
    }

    // Saturate the real pipe, then make room for exactly one atomic write. No concurrent
    // reader or scheduler timing is involved in the short logical transfer.
    size_t fillPipe(int reader, int writer) {
        const auto flags = fcntl(writer, F_GETFL);
        REQUIRE(flags >= 0 && fcntl(writer, F_SETFL, flags | O_NONBLOCK) == 0);
        std::array<uint8_t, PIPE_BUF> filler{};
        size_t filled = 0;

        while (write(writer, filler.data(), filler.size()) == PIPE_BUF) {
            filled += filler.size();
        }

        REQUIRE(errno == EAGAIN && filled >= filler.size());
        REQUIRE(read(reader, filler.data(), filler.size()) == PIPE_BUF);
        return filled - filler.size();
    }

    void checkPartialCount() {
        int ends[2];
        REQUIRE(pipe(ends) == 0);
        const auto filler = fillPipe(ends[0], ends[1]);

        std::array<uint8_t, requestLength> payload{};
        for (size_t i = 0; i < payload.size(); ++i) {
            payload[i] = static_cast<uint8_t>(i);
        }

        const forge_rt_backing backing{payload.size(), payload.data(), nullptr, 0};
        const forge_rt_region_template region{sourceAddress, payload.size(), 0, 0, FORGE_RT_READ};
        constexpr forge_rt_import imports[]{{"kernel32.dll", "GetStdHandle"},
                                            {"kernel32.dll", "WriteFile"}};
        const forge_rt_artifact artifact{FORGE_RT_ARTIFACT_VERSION,
                                         sourceAddress,
                                         payload.size(),
                                         1,
                                         1,
                                         &backing,
                                         1,
                                         &region,
                                         1,
                                         imports,
                                         2,
                                         writePartial};
        forge_rt_process *process = nullptr;
        const int saved = dup(STDOUT_FILENO);
        REQUIRE(saved >= 0 && dup2(ends[1], STDOUT_FILENO) == STDOUT_FILENO);
        REQUIRE(forge_rt_process_create(FORGE_RT_ABI_VERSION, &process) == FORGE_RT_OK);
        REQUIRE(forge_rt_process_register(process, &artifact) == FORGE_RT_OK);
        REQUIRE(dup2(saved, STDOUT_FILENO) == STDOUT_FILENO && close(saved) == 0);
        REQUIRE(close(ends[1]) == 0);
        // The reader stays open until after process completion, so EPIPE cannot occur.
        REQUIRE(forge_rt_process_allow_host_output_signals(process) == FORGE_RT_OK);
        forge_rt_process_result result{};
        REQUIRE(forge_rt_process_run(process, nullptr, &result) == FORGE_RT_OK);
        REQUIRE(forge_rt_process_destroy(process) == FORGE_RT_OK);
        REQUIRE(result.kind == FORGE_RT_RETURNED);

        std::vector<uint8_t> received;
        std::array<uint8_t, PIPE_BUF> chunk{};
        ssize_t size;

        while ((size = read(ends[0], chunk.data(), chunk.size())) > 0) {
            received.insert(received.end(), chunk.begin(), chunk.begin() + size);
        }

        REQUIRE(size == 0 && close(ends[0]) == 0);
        REQUIRE(received.size() == filler + result.value);
        REQUIRE(std::ranges::equal(std::span(received).subspan(filler),
                                   std::span(payload).first(result.value)));
    }
} // namespace

void testRuntimeWrite() {
    checkDescriptorOwnership();
    constexpr std::array success{Attempt{-1, EINTR}, Attempt{2, 0}, Attempt{-1, EINTR},
                                 Attempt{3, 0}};
    constexpr std::array errorAfterPrefix{Attempt{1, 0}, Attempt{2, 0}, Attempt{-1, EPIPE}};
    constexpr std::array blockedAfterPrefix{Attempt{2, 0}, Attempt{-1, EAGAIN}};
    constexpr std::array stopped{Attempt{2, 0}, Attempt{0, 0}};
    checkWrites(success, 5, 0);
    checkWrites(errorAfterPrefix, 3, EPIPE);
    checkWrites(blockedAfterPrefix, 2, EAGAIN);
    checkWrites(stopped, 2, EIO);
    checkPartialCount();
}
