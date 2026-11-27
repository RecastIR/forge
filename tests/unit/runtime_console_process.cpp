#include "../../runtime/src/compat/process_state.h"
#include "../../runtime/src/core/instance.h"
#include "../../runtime/src/platform/darwin/io.h"
#include <forge/msvcrt_process.h>
#include <forge/process.h>
#include <forge/service_signature.h>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <pthread.h>
#include <string>
#include <string_view>
#ifdef __APPLE__
#include <semaphore.h>
#endif
#include <sys/resource.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace {
    void require(bool ok, const char *expression, int line) {
        if (!ok) {
            std::fprintf(stderr, "runtime_console_process.cpp:%d: %s\n", line, expression);
            std::abort();
        }
    }

#define REQUIRE(...) require((__VA_ARGS__), #__VA_ARGS__, __LINE__)
    constexpr uint32_t stdInput = 0xfffffff6, stdOutput = 0xfffffff5, stdError = 0xfffffff4;
    constexpr uint32_t initialError = 1234;
    constexpr uint64_t source = 0x2100, countSlot = FORGE_RT_ENTRY_RSP - 8;
    constexpr uint8_t payload = 'G';
    constexpr forge_rt_backing backing{1, &payload, nullptr, 0};
    constexpr forge_rt_region_template region{source, 1, 0, 0, FORGE_RT_READ};
    constexpr forge_rt_import imports[]{{"kernel32.dll", "GetStdHandle"},
                                        {"kernel32.dll", "WriteFile"}};
    constexpr forge_rt_import fatalImport{"msvcrt.dll", "_amsg_exit"};

    uint64_t handle(const forge_rt_execution &execution, uint32_t selector) {
        uint64_t value = 0;
        REQUIRE(forge_rt_get_std_handle(execution.instance, execution.thread, selector, &value) ==
                FORGE_RT_OK);
        return value;
    }

    uint32_t lastError(const forge_rt_execution &execution) {
        uint32_t value = 0;
        REQUIRE(forge_rt_get_last_error(execution.instance, execution.thread, &value) ==
                FORGE_RT_OK);
        return value;
    }

    struct WriteResult {
        forge_rt_status status;
        int32_t success;
        uint32_t count;
    };

    WriteResult writeByte(const forge_rt_execution &execution, uint64_t target) {
        forge_rt_invocation_token token = 0;
        REQUIRE(forge_rt_current_invocation(execution.instance, execution.thread, &token) ==
                FORGE_RT_OK);
        uint32_t count = UINT32_MAX;
        forge_rt_memory_fault fault{};
        REQUIRE(forge_rt_write_guest(execution.instance, execution.thread, token, countSlot,
                                     sizeof(count), &count, sizeof(count), &fault) == FORGE_RT_OK);
        int32_t success = -1;
        const auto status = forge_rt_write_file(execution.instance, execution.thread, target,
                                                source, 1, countSlot, 0, &success, &fault);
        REQUIRE(forge_rt_read_guest(execution.instance, execution.thread, token, countSlot,
                                    sizeof(count), &count, sizeof(count), &fault) == FORGE_RT_OK);
        return {status, success, count};
    }

    // Both processes run after their host has redirected stdout a second time.
    void checkHandles(forge_rt_execution *execution) {
        REQUIRE(lastError(*execution) == 0);
        REQUIRE(forge_rt_set_last_error(execution->instance, execution->thread, initialError) ==
                FORGE_RT_OK);
        const auto out = handle(*execution, stdOutput);
        const auto err = handle(*execution, stdError);
        REQUIRE(out > 2 && out != UINT64_MAX && err > 2 && err != UINT64_MAX && out != err);
        REQUIRE(handle(*execution, stdInput) == 0);
        REQUIRE(lastError(*execution) == initialError);
        REQUIRE(handle(*execution, 0) == UINT64_MAX && lastError(*execution) == 6);

        for (const uint64_t invalid : {uint64_t{1}, uint64_t{2}, execution->rcx}) {
            const auto failed = writeByte(*execution, invalid);
            REQUIRE(failed.status == FORGE_RT_OK && failed.success == 0 && failed.count == 0);
            REQUIRE(lastError(*execution) == 6);
        }

        const auto written = writeByte(*execution, out);
        REQUIRE(written.status == FORGE_RT_OK && written.success == 1 && written.count == 1);
        REQUIRE(lastError(*execution) == 6);
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, out, {}, 0};
    }

    void attemptFailedWrite(forge_rt_execution *execution) {
        const auto out = handle(*execution, stdOutput);
        REQUIRE(forge_rt_set_last_error(execution->instance, execution->thread, initialError) ==
                FORGE_RT_OK);
        const auto written = writeByte(*execution, out);
        REQUIRE(written.count == 0);

        if (written.status == FORGE_RT_HOST_CONFIGURATION) {
            REQUIRE(written.success == -1 && lastError(*execution) == initialError);
            execution->result = {FORGE_RT_RUNTIME_FAILURE, written.status, 0, {}, 0};
            return;
        }

        REQUIRE(written.status == FORGE_RT_OK && written.success == 0);
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, lastError(*execution), {}, 0};
    }

    using Process = std::unique_ptr<forge_rt_process, decltype(&forge_rt_process_destroy)>;

    forge_rt_artifact consoleArtifact(void (*entry)(forge_rt_execution *),
                                      const forge_rt_region_template &row = region) {
        return {FORGE_RT_ARTIFACT_VERSION, source, 16, 8, 8, &backing, 1, &row, 1, imports,
                std::size(imports),        entry};
    }

    Process registered(const forge_rt_artifact &artifact) {
        forge_rt_process *raw = nullptr;
        REQUIRE(forge_rt_process_create(FORGE_RT_ABI_VERSION, &raw) == FORGE_RT_OK);
        Process process(raw, forge_rt_process_destroy);
        REQUIRE(forge_rt_process_register(raw, &artifact) == FORGE_RT_OK);
        return process;
    }

    forge_rt_process_result run(const Process &process, uint64_t foreignHandle = 0) {
        forge_rt_process_result result{};
        const forge_rt_entry_inputs inputs{foreignHandle, 0};
        REQUIRE(forge_rt_process_run(process.get(), &inputs, &result) == FORGE_RT_OK);
        return result;
    }

    void checkRedirection() {
        const auto artifact = consoleArtifact(checkHandles);
        const int savedInput = fcntl(STDIN_FILENO, F_DUPFD_CLOEXEC, 3);

        if (savedInput < 0) {
            // Keep temporary file descriptors outside the standard streams even in a headless host.
            REQUIRE(dup2(STDERR_FILENO, STDIN_FILENO) == STDIN_FILENO);
        }

        std::unique_ptr<FILE, decltype(&std::fclose)> firstFile(std::tmpfile(), std::fclose);
        std::unique_ptr<FILE, decltype(&std::fclose)> secondFile(std::tmpfile(), std::fclose);
        REQUIRE(firstFile && secondFile);
        const int savedOutput = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
        REQUIRE(savedOutput >= 0 && close(STDIN_FILENO) == 0);

        REQUIRE(dup2(fileno(firstFile.get()), STDOUT_FILENO) == STDOUT_FILENO);
        auto first = registered(artifact);
        REQUIRE(dup2(fileno(secondFile.get()), STDOUT_FILENO) == STDOUT_FILENO);
        auto second = registered(artifact);
        const auto firstResult = run(first);
        REQUIRE(firstResult.kind == FORGE_RT_RETURNED);
        first.reset();
        const auto secondResult = run(second, firstResult.value);
        REQUIRE(secondResult.kind == FORGE_RT_RETURNED && secondResult.value != firstResult.value);
        second.reset();
        REQUIRE(write(STDOUT_FILENO, "H", 1) == 1);
        REQUIRE(dup2(savedOutput, STDOUT_FILENO) == STDOUT_FILENO && close(savedOutput) == 0);

        if (savedInput >= 0) {
            REQUIRE(dup2(savedInput, STDIN_FILENO) == STDIN_FILENO && close(savedInput) == 0);
        }

        REQUIRE(std::fseek(firstFile.get(), 0, SEEK_SET) == 0);
        REQUIRE(std::fseek(secondFile.get(), 0, SEEK_SET) == 0);
        REQUIRE(std::fgetc(firstFile.get()) == payload && std::fgetc(firstFile.get()) == EOF);
        REQUIRE(std::fgetc(secondFile.get()) == payload && std::fgetc(secondFile.get()) == 'H' &&
                std::fgetc(secondFile.get()) == EOF);
    }

    void handleOutputSignal(int) {}

    void fatalEntry(forge_rt_execution *execution) {
        auto *instance = execution->instance;
        const auto thread = execution->thread;
        REQUIRE(lastError(*execution) == 0);
        REQUIRE(forge_rt_set_last_error(instance, thread, initialError) == FORGE_RT_OK);
        REQUIRE(forge_rt_msvcrt_amsg_exit(instance, 0, 31) == FORGE_RT_INVALID_THREAD);
        REQUIRE(forge_rt_msvcrt_amsg_exit(instance, thread, static_cast<int32_t>(execution->rcx)) ==
                FORGE_RT_OK);
        REQUIRE(forge_rt_msvcrt_amsg_exit(instance, thread, 31) == FORGE_RT_INVALID_STATE);
        REQUIRE(lastError(*execution) == initialError);
    }

    constexpr forge_rt_artifact fatalArtifact{FORGE_RT_ARTIFACT_VERSION,
                                              source,
                                              16,
                                              8,
                                              8,
                                              nullptr,
                                              0,
                                              nullptr,
                                              0,
                                              &fatalImport,
                                              1,
                                              fatalEntry};

    Process registeredWithStream(const forge_rt_artifact &artifact, int target, int descriptor) {
        const int saved = fcntl(target, F_DUPFD_CLOEXEC, 3);
        REQUIRE(saved >= 0 || errno == EBADF);

        if (descriptor >= 0) {
            REQUIRE(dup2(descriptor, target) == target);
        } else if (saved >= 0) {
            REQUIRE(close(target) == 0);
        }

        auto process = registered(artifact);

        if (saved >= 0) {
            REQUIRE(dup2(saved, target) == target && close(saved) == 0);
        } else if (descriptor >= 0) {
            REQUIRE(close(target) == 0);
        }

        return process;
    }

    Process registeredWithStderr(const forge_rt_artifact &artifact, int descriptor) {
        return registeredWithStream(artifact, STDERR_FILENO, descriptor);
    }

    void expectFatal(const Process &process, int32_t errorNumber) {
        const auto result = run(process, static_cast<uint32_t>(errorNumber));
        REQUIRE(result.kind == FORGE_RT_EXIT_PROCESS && result.status == FORGE_RT_OK &&
                result.value == 255);
        forge_rt_process_state state = 0;
        REQUIRE(forge_rt_process_get_state(process.get(), &state) == FORGE_RT_OK &&
                state == FORGE_RT_PROCESS_EXITED);
    }

    void checkFatalOutputFailures() {
        REQUIRE(forge_rt_msvcrt_amsg_exit(nullptr, 0, 31) == FORGE_RT_INVALID_ARGUMENT);
        expectFatal(registeredWithStderr(fatalArtifact, -1), 31);
        int ends[2];
        REQUIRE(pipe(ends) == 0);
        expectFatal(registeredWithStderr(fatalArtifact, ends[0]), 31);

        // A readable pipe would accept the message. Without signal safety the service must
        // leave it empty, release its duplicate on exit, and preserve the host disposition.
        struct sigaction policy{}, previous{}, observed{};
        REQUIRE(sigemptyset(&policy.sa_mask) == 0);
        policy.sa_handler = SIG_DFL;
        REQUIRE(sigaction(SIGPIPE, &policy, &previous) == 0);
        auto unsafe = registeredWithStderr(fatalArtifact, ends[1]);
        REQUIRE(close(ends[1]) == 0);
        expectFatal(unsafe, 31);
        char byte;
        REQUIRE(fcntl(ends[0], F_SETFL, O_NONBLOCK) == 0);
        REQUIRE(read(ends[0], &byte, 1) == 0 && close(ends[0]) == 0);
        REQUIRE(sigaction(SIGPIPE, nullptr, &observed) == 0 && observed.sa_handler == SIG_DFL);

        // A safely reported EPIPE also leaves the guest exit code intact.
        policy.sa_handler = SIG_IGN;
        REQUIRE(sigaction(SIGPIPE, &policy, nullptr) == 0);
        REQUIRE(pipe(ends) == 0 && close(ends[0]) == 0);
        expectFatal(registeredWithStderr(fatalArtifact, ends[1]), 31);
        REQUIRE(close(ends[1]) == 0);
        REQUIRE(sigaction(SIGPIPE, &previous, &observed) == 0 && observed.sa_handler == SIG_IGN);
    }

    bool fileContentsEqual(FILE *file, std::string_view expected) {
        REQUIRE(std::fseek(file, 0, SEEK_SET) == 0);

        for (const char byte : expected) {
            const int observed = std::fgetc(file);
            if (observed == EOF || observed != static_cast<unsigned char>(byte)) {
                return false;
            }
        }

        return std::fgetc(file) == EOF && std::feof(file) && !std::ferror(file);
    }

    std::string readObservation(const std::filesystem::path &path) {
        std::ifstream input(path, std::ios::binary | std::ios::ate);
        const std::streamoff size = input.tellg();

        if (size >= 0) {
            std::string bytes(static_cast<size_t>(size), '\0');
            if (input.seekg(0) && input.read(bytes.data(), size)) {
                return bytes;
            }
        }

        std::fprintf(stderr, "Cannot read Windows observation %s\n", path.c_str());
        std::abort();
    }

    constexpr auto scanLimit = forge::win64::crtPutsScanLimit;
    constexpr auto highBase = UINT64_MAX - scanLimit - 4;

    void putsMemory(forge_rt_execution *execution) {
        auto *instance = execution->instance;
        const auto thread = execution->thread;
        forge_rt_invocation_token token{};
        REQUIRE(forge_rt_current_invocation(instance, thread, &token) == FORGE_RT_OK);
        int32_t result = 73;
        forge_rt_memory_fault fault{};
        const auto puts = [&](uint64_t address) {
            return forge_rt_msvcrt_puts(instance, thread, address, &result, &fault);
        };
        REQUIRE(forge_rt_msvcrt_puts(instance, 0, 0, &result, &fault) == FORGE_RT_INVALID_THREAD);
        std::thread outside(
            [&] { REQUIRE(puts(0) == FORGE_RT_INVALID_INVOCATION && result == 73); });
        outside.join();
        REQUIRE(puts(highBase) == FORGE_RT_UNSUPPORTED_CRT_STREAM && result == 73);

        struct ExpectedFault {
            uint64_t argument, address;
            uint32_t reason;
        };

        for (const auto &[address, invalid, reason] : std::initializer_list<ExpectedFault>{
                 {highBase + scanLimit + 1, highBase + scanLimit + 2, FORGE_RT_FAULT_PERMISSION},
                 {UINT64_MAX - 1, UINT64_MAX - 1, FORGE_RT_FAULT_UNMAPPED},
                 {UINT64_MAX, UINT64_MAX, FORGE_RT_FAULT_OVERFLOW},
                 {FORGE_RT_ENTRY_RSP, FORGE_RT_ENTRY_RSP, FORGE_RT_FAULT_STACK}}) {
            REQUIRE(puts(address) == FORGE_RT_GUEST_FAULT && result == 73);
            REQUIRE(fault.address == invalid && fault.access == FORGE_RT_READ &&
                    fault.reason == reason);
        }

        auto &streams = *instance->windows->streams;
        REQUIRE(!streams.buffers[1] && streams.files[1].flags == 2);
        if (execution->rcx == 'A') {
            REQUIRE(puts(highBase + 1) == FORGE_RT_OK && result == 0);
        }

        const uint8_t message[]{static_cast<uint8_t>(execution->rcx), 0};
        const auto stack = FORGE_RT_ENTRY_RSP - sizeof(message);
        REQUIRE(forge_rt_write_guest(instance, thread, token, stack, sizeof(message), message,
                                     sizeof(message), &fault) == FORGE_RT_OK);
        REQUIRE(puts(stack) == FORGE_RT_OK && result == 0);

        uint64_t heap{};
        REQUIRE(forge_rt_msvcrt_malloc(instance, thread, sizeof(message), &heap) == FORGE_RT_OK &&
                heap);
        REQUIRE(forge_rt_write_guest(instance, thread, token, heap, sizeof(message), message,
                                     sizeof(message), &fault) == FORGE_RT_OK);
        REQUIRE(puts(heap) == FORGE_RT_OK && result == 0);
        REQUIRE(forge_rt_msvcrt_free(instance, thread, heap) == FORGE_RT_OK);

        result = 73;
        REQUIRE(puts(streams.mapping.base + sizeof(forge::runtime::LegacyFile) + 24) ==
                    FORGE_RT_UNSUPPORTED_CRT_STREAM &&
                result == 73);
        if (execution->rcx == 'B') {
            REQUIRE(puts(streams.files[1].base) == FORGE_RT_UNSUPPORTED_CRT_STREAM && result == 73);
        }
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, 42, {}, 0};
        REQUIRE(puts(0) == FORGE_RT_INVALID_STATE && result == 73);
    }

    void checkPutsMemory() {
        std::string bytes(scanLimit + 5, 'L');
        bytes[scanLimit] = 0;
        const forge_rt_backing data{bytes.size(), bytes.data(), nullptr, 0};
        const forge_rt_region_template rows[]{
            {highBase, scanLimit + 2, 0, 0, FORGE_RT_READ},
            {highBase + scanLimit + 2, 1, 0, scanLimit + 2, FORGE_RT_EXECUTE},
            {UINT64_MAX, 1, 0, scanLimit + 4, FORGE_RT_READ}};
        constexpr forge_rt_import output{"msvcrt.dll", "puts"};
        const forge_rt_artifact artifact{FORGE_RT_ARTIFACT_VERSION,
                                         highBase,
                                         bytes.size(),
                                         0,
                                         0,
                                         &data,
                                         1,
                                         rows,
                                         std::size(rows),
                                         &output,
                                         1,
                                         putsMemory};

        std::unique_ptr<FILE, decltype(&std::fclose)> a(std::tmpfile(), std::fclose);
        std::unique_ptr<FILE, decltype(&std::fclose)> b(std::tmpfile(), std::fclose);
        REQUIRE(a && b);
        auto first = registeredWithStream(artifact, STDOUT_FILENO, fileno(a.get()));
        auto second = registeredWithStream(artifact, STDOUT_FILENO, fileno(b.get()));
        REQUIRE(run(first, 'A').value == 42 && run(second, 'B').value == 42);
        REQUIRE(fileContentsEqual(a.get(), std::string(scanLimit - 1, 'L') + "\r\nA\r\nA\r\n"));
        REQUIRE(fileContentsEqual(b.get(), "B\r\nB\r\n"));
    }

    void streamIdentity(forge_rt_execution *execution) {
        const auto thread = execution->thread;
        auto *instance = execution->instance;
        uint64_t base = 0, elements = UINT64_MAX;
        forge_rt_memory_fault fault{};
        REQUIRE(forge_rt_msvcrt_iob_func(instance, 0, &base) == FORGE_RT_INVALID_THREAD);
        REQUIRE(forge_rt_msvcrt_iob_func(instance, thread, &base) == FORGE_RT_OK && base % 8 == 0);
        const auto output = base + 96;
        const auto put = [&](uint64_t stream, uint64_t address, uint64_t size, uint64_t count) {
            return forge_rt_msvcrt_fwrite(instance, thread, address, size, count, stream, &elements,
                                          &fault);
        };
        for (const auto invalid : {output + 1, base + 144, UINT64_MAX, execution->rcx}) {
            if (invalid) {
                REQUIRE(put(invalid, source, 1, 1) == FORGE_RT_UNSUPPORTED_CRT_STREAM);
                REQUIRE(elements == UINT64_MAX);
            }
        }
        REQUIRE(put(base, source + 1, 1, 1) == FORGE_RT_GUEST_FAULT && fault.address == source + 1);
        REQUIRE(put(output, source, 2, 1) == FORGE_RT_GUEST_FAULT);
        REQUIRE(fault.address == source + 1 && fault.access == FORGE_RT_READ &&
                fault.reason == FORGE_RT_FAULT_UNMAPPED && elements == UINT64_MAX);
        REQUIRE(forge_rt_set_last_error(instance, thread, initialError) == FORGE_RT_OK);
        for (const auto target : {uint64_t{0}, output + 1}) {
            REQUIRE(put(target, UINT64_MAX, 2, 0) == FORGE_RT_OK && elements == 0);
        }
        REQUIRE(put(0, source, 1, 1) == FORGE_RT_OK && elements == 0);
        REQUIRE(put(output, 0, 1, 1) == FORGE_RT_OK && elements == 0);
        REQUIRE(put(output, UINT64_MAX, UINT64_MAX, 2) == FORGE_RT_OK && elements == 0);
        REQUIRE(instance->windows->crtErrno == 22 && lastError(*execution) == initialError);
        REQUIRE(put(output, source, 1, 1) == FORGE_RT_OK && elements == 1);
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, output, {}, 0};
        REQUIRE(forge_rt_msvcrt_iob_func(instance, thread, &base) == FORGE_RT_INVALID_STATE);
        REQUIRE(put(output, source, 1, 1) == FORGE_RT_INVALID_STATE);
    }

    void checkStreamIdentity() {
        constexpr forge_rt_import streams[]{{"msvcrt.dll", "__iob_func"}, {"msvcrt.dll", "fwrite"}};
        auto artifact = consoleArtifact(streamIdentity);
        artifact.imports = streams;
        artifact.importCount = std::size(streams);
        std::unique_ptr<FILE, decltype(&std::fclose)> firstFile(std::tmpfile(), std::fclose);
        std::unique_ptr<FILE, decltype(&std::fclose)> secondFile(std::tmpfile(), std::fclose);
        REQUIRE(firstFile && secondFile);
        auto first = registeredWithStderr(artifact, fileno(firstFile.get()));
        auto second = registeredWithStderr(artifact, fileno(secondFile.get()));
        const auto original = run(first);
        REQUIRE(original.kind == FORGE_RT_RETURNED && original.value);
        const auto foreign = run(second, original.value);
        REQUIRE(foreign.kind == FORGE_RT_RETURNED && foreign.value != original.value);
        first.reset();
        second.reset();
        auto fresh = registeredWithStderr(artifact, fileno(secondFile.get()));
        const auto retired = run(fresh, foreign.value);
        REQUIRE(retired.kind == FORGE_RT_RETURNED && retired.value != foreign.value);
        REQUIRE(fileContentsEqual(firstFile.get(), "G") &&
                fileContentsEqual(secondFile.get(), "GG"));
    }

    void retryStreamWrite(forge_rt_execution *execution) {
        auto *instance = execution->instance;
        uint64_t base = 0, elements = UINT64_MAX;
        forge_rt_memory_fault fault{};
        REQUIRE(forge_rt_msvcrt_iob_func(instance, execution->thread, &base) == FORGE_RT_OK);
        const auto put = [&](uint64_t address, uint64_t size) {
            return forge_rt_msvcrt_fwrite(instance, execution->thread, address, 1, size, base + 96,
                                          &elements, &fault);
        };

        struct rlimit previous{};
        REQUIRE(getrlimit(RLIMIT_FSIZE, &previous) == 0);
        const struct rlimit one{1, previous.rlim_max};
        REQUIRE(setrlimit(RLIMIT_FSIZE, &one) == 0);
        auto &streams = *instance->windows->streams;
        const auto &file = streams.files[2];
        if (execution->rcx) {
            // The file is already at its limit. The direct prefix fails before the tail starts.
            REQUIRE(put(source, 4097) == FORGE_RT_OK && elements == 0 && file.base == 0);
            const auto &reserved = streams.buffers[2];
            REQUIRE(reserved && (file.flags & 0x20));
            elements = UINT64_MAX;
            REQUIRE(put(reserved->mapping.base + 1, 8) == FORGE_RT_UNSUPPORTED_CRT_STREAM);
            REQUIRE(elements == UINT64_MAX && file.base == 0);
            REQUIRE(put(source + 4096, 1) == FORGE_RT_OK && elements == 1);
        } else {
            // Fill via two calls so the previous block is buffered. Its flush accepts only 'A'.
            REQUIRE(put(source, 1) == FORGE_RT_OK && elements == 1);
            REQUIRE(put(source + 1, 4095) == FORGE_RT_OK && elements == 4095);
            REQUIRE(put(source + 4096, 1) == FORGE_RT_OK && elements == 0);
            REQUIRE((file.flags & 0x20) && file.ptr == file.base + 1 && file.count == 4095);
        }

        REQUIRE(setrlimit(RLIMIT_FSIZE, &previous) == 0);
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, 42, {}, 0};
    }

    void checkStreamWriteRetries() {
        std::array<uint8_t, 4097> bytes{'A', '\n', '\n'};
        bytes.back() = 'Z';
        const forge_rt_backing data{bytes.size(), bytes.data(), nullptr, 0};
        const forge_rt_region_template row{source, bytes.size(), 0, 0, FORGE_RT_READ};
        constexpr forge_rt_import output{"msvcrt.dll", "fwrite"};
        auto artifact = consoleArtifact(retryStreamWrite, row);
        artifact.size = bytes.size();
        artifact.backings = &data;
        artifact.imports = &output;
        artifact.importCount = 1;

        struct sigaction ignore{}, previous{};
        ignore.sa_handler = SIG_IGN;
        REQUIRE(sigemptyset(&ignore.sa_mask) == 0 && sigaction(SIGXFSZ, &ignore, &previous) == 0);
        for (const bool full : {false, true}) {
            std::unique_ptr<FILE, decltype(&std::fclose)> file(std::tmpfile(), std::fclose);
            REQUIRE(file && (!full || write(fileno(file.get()), "!", 1) == 1));
            const auto result = run(registeredWithStderr(artifact, fileno(file.get())), full);
            REQUIRE(result.kind == FORGE_RT_RETURNED && result.value == 42);
            REQUIRE(fileContentsEqual(file.get(), full ? "!Z" : "AZ"));
        }
        REQUIRE(sigaction(SIGXFSZ, &previous, nullptr) == 0);
    }

    void pendingFatal(forge_rt_execution *execution) {
        uint64_t base = 0, count = 0;
        forge_rt_memory_fault fault{};
        REQUIRE(forge_rt_msvcrt_iob_func(execution->instance, execution->thread, &base) ==
                FORGE_RT_OK);
        REQUIRE(forge_rt_msvcrt_fwrite(execution->instance, execution->thread, source, 1, 1,
                                       base + 96, &count, &fault) == FORGE_RT_OK &&
                count == 1);
        REQUIRE(forge_rt_msvcrt_amsg_exit(execution->instance, execution->thread, 8) ==
                FORGE_RT_OK);
    }

    void checkStreamTermination() {
        constexpr forge_rt_import dependencies[]{{"msvcrt.dll", "fwrite"}, fatalImport};
        auto artifact = consoleArtifact(pendingFatal);
        artifact.imports = dependencies;
        artifact.importCount = std::size(dependencies);
        std::unique_ptr<FILE, decltype(&std::fclose)> err(std::tmpfile(), std::fclose);
        REQUIRE(err != nullptr);
        auto fatal = registeredWithStderr(artifact, fileno(err.get()));
        const auto result = run(fatal);
        REQUIRE(result.kind == FORGE_RT_EXIT_PROCESS && result.value == 255);
        REQUIRE(fileContentsEqual(
            err.get(), "\r\nruntime error R6008\r\n- not enough space for arguments\r\nG"));

        int ends[2];
        REQUIRE(pipe(ends) == 0 && close(ends[0]) == 0);
        struct sigaction action{}, previous{};
        action.sa_handler = SIG_DFL;
        REQUIRE(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGPIPE, &action, &previous) == 0);
        artifact.entry = streamIdentity;
        auto unsafe = registeredWithStderr(artifact, ends[1]);
        const auto stopped = run(unsafe);
        REQUIRE(stopped.kind == FORGE_RT_RUNTIME_FAILURE &&
                stopped.status == FORGE_RT_HOST_CONFIGURATION);

        action.sa_handler = SIG_IGN;
        REQUIRE(sigaction(SIGPIPE, &action, nullptr) == 0);
        auto safe = registeredWithStderr(artifact, ends[1]);
        REQUIRE(run(safe).kind == FORGE_RT_RETURNED);
        REQUIRE(sigaction(SIGPIPE, &previous, nullptr) == 0 && close(ends[1]) == 0);
    }

    void checkFatalObservation(const std::filesystem::path &observations, int32_t errorNumber) {
        const std::string prefix = errorNumber < 0 ? "" : "sweep-";
        const auto directory = observations / (prefix + std::to_string(errorNumber) + "-pipe");
        std::unique_ptr<FILE, decltype(&std::fclose)> out(std::tmpfile(), std::fclose);
        std::unique_ptr<FILE, decltype(&std::fclose)> err(std::tmpfile(), std::fclose);
        REQUIRE(out && err);
        const int saved = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
        REQUIRE(saved >= 0 && dup2(fileno(out.get()), STDOUT_FILENO) == STDOUT_FILENO);
        auto process = registeredWithStderr(fatalArtifact, fileno(err.get()));
        const auto result = run(process, static_cast<uint32_t>(errorNumber));
        REQUIRE(dup2(saved, STDOUT_FILENO) == STDOUT_FILENO && close(saved) == 0);

        const auto compare = [&](const char *field, bool matches) {
            if (!matches) {
                std::fprintf(stderr, "_amsg_exit(%d) %s differs from Windows capture %s\n",
                             errorNumber, field, directory.c_str());
                std::abort();
            }
        };
        const auto exit = "exit=" + std::to_string(result.value) + "\n";
        compare("exit", result.kind == FORGE_RT_EXIT_PROCESS && result.status == FORGE_RT_OK &&
                            result.fault == 0 && result.memory.address == 0 &&
                            result.memory.access == 0 && result.memory.reason == 0 &&
                            exit == readObservation(directory / "observation.txt"));
        compare("stdout", fileContentsEqual(out.get(), readObservation(directory / "stdout.bin")));
        compare("stderr", fileContentsEqual(err.get(), readObservation(directory / "stderr.bin")));
    }

    void checkFatalProcessIsolation(int32_t errorNumber, std::string_view message) {
        std::unique_ptr<FILE, decltype(&std::fclose)> firstFile(std::tmpfile(), std::fclose);
        std::unique_ptr<FILE, decltype(&std::fclose)> secondFile(std::tmpfile(), std::fclose);
        REQUIRE(firstFile && secondFile);
        auto ordinary = fatalArtifact;
        ordinary.entry = [](forge_rt_execution *execution) {
            REQUIRE(lastError(*execution) == 0);
            execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, 42, {}, 0};
        };

        auto first = registeredWithStderr(fatalArtifact, fileno(firstFile.get()));
        auto second = registeredWithStderr(ordinary, fileno(secondFile.get()));
        expectFatal(first, errorNumber);
        const auto result = run(second);
        REQUIRE(result.kind == FORGE_RT_RETURNED && result.status == FORGE_RT_OK &&
                result.value == 42);
        REQUIRE(fileContentsEqual(firstFile.get(), message));
        REQUIRE(fileContentsEqual(secondFile.get(), ""));
        REQUIRE(write(fileno(secondFile.get()), "H", 1) == 1);
    }

    void checkFatalPartialWrite(int32_t errorNumber, std::string_view message) {
        constexpr size_t prefixLength = 3;
        REQUIRE(message.size() > prefixLength);
        std::unique_ptr<FILE, decltype(&std::fclose)> file(std::tmpfile(), std::fclose);
        REQUIRE(file != nullptr);
        auto process = registeredWithStderr(fatalArtifact, fileno(file.get()));

        struct rlimit previousLimit{};
        REQUIRE(getrlimit(RLIMIT_FSIZE, &previousLimit) == 0);
        struct sigaction policy{}, previousAction{};
        REQUIRE(sigemptyset(&policy.sa_mask) == 0);
        policy.sa_handler = SIG_IGN;
        REQUIRE(sigaction(SIGXFSZ, &policy, &previousAction) == 0);
        const struct rlimit limit{prefixLength, previousLimit.rlim_max};
        REQUIRE(setrlimit(RLIMIT_FSIZE, &limit) == 0);
        expectFatal(process, errorNumber);
        REQUIRE(setrlimit(RLIMIT_FSIZE, &previousLimit) == 0);
        REQUIRE(sigaction(SIGXFSZ, &previousAction, nullptr) == 0);
        REQUIRE(fileContentsEqual(file.get(), message.substr(0, prefixLength)));
    }

    constexpr forge_rt_process_result completions[] = {
        {FORGE_RT_RETURNED, FORGE_RT_OK, 17, {}, 0},
        {FORGE_RT_EXIT_PROCESS, FORGE_RT_OK, 42, {}, 0},
        {FORGE_RT_EXECUTION_FAULT, FORGE_RT_GUEST_FAULT, 0, {}, FORGE_RT_FAULT_CONTROL},
        {FORGE_RT_UNSUPPORTED, FORGE_RT_OK, 0, {}, 0},
        {FORGE_RT_RUNTIME_FAILURE, FORGE_RT_INTERNAL_ERROR, 0, {}, 0}};

    void finishCapture(forge_rt_execution *execution) {
        REQUIRE(execution->rcx < std::size(completions));
        const auto &completion = completions[execution->rcx];

        if (completion.kind == FORGE_RT_EXIT_PROCESS) {
            REQUIRE(forge_rt_exit_process(execution->instance, execution->thread, 42) ==
                    FORGE_RT_OK);
        } else {
            execution->result = completion;
        }
    }

    // The caller owns the read end. Once stdout is restored only a captured duplicate can write.
    int captureRegistrationOutput(auto registerProcess) {
        int ends[2];
        REQUIRE(pipe(ends) == 0 && fcntl(ends[0], F_SETFL, O_NONBLOCK) == 0);
        const int saved = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
        REQUIRE(saved >= 0 && dup2(ends[1], STDOUT_FILENO) == STDOUT_FILENO && close(ends[1]) == 0);
        registerProcess();
        REQUIRE(dup2(saved, STDOUT_FILENO) == STDOUT_FILENO && close(saved) == 0);
        return ends[0];
    }

    void checkCaptureCleanup(bool reject, size_t completion = std::size(completions)) {
        auto testRegion = region;

        if (reject) {
            testRegion.backing = 1; // Reject during staged image binding, after capture.
        }

        const auto artifact = consoleArtifact(finishCapture, testRegion);
        forge_rt_process *raw = nullptr;
        REQUIRE(forge_rt_process_create(FORGE_RT_ABI_VERSION, &raw) == FORGE_RT_OK);
        Process process(raw, forge_rt_process_destroy);
        const int reader = captureRegistrationOutput([&] {
            const auto status = forge_rt_process_register(process.get(), &artifact);
            REQUIRE(status == (reject ? FORGE_RT_INVALID_ARGUMENT : FORGE_RT_OK));
        });
        char byte;

        if (!reject) {
            REQUIRE(read(reader, &byte, 1) == -1 && errno == EAGAIN);

            if (completion < std::size(completions)) {
                const auto result = run(process, completion);
                REQUIRE(result.kind == completions[completion].kind);
            } else {
                REQUIRE(forge_rt_process_close(process.get()) == FORGE_RT_OK);
            }
        }

        // EOF proves even the staged duplicate expired, while the process handle is still live.
        REQUIRE(read(reader, &byte, 1) == 0 && close(reader) == 0);
    }

    void writeRegisteredEnvironment(forge_rt_execution *execution) {
        auto *instance = execution->instance;
        const auto thread = execution->thread;
        forge_rt_invocation_token token = 0;
        REQUIRE(forge_rt_current_invocation(instance, thread, &token) == FORGE_RT_OK);
        forge_rt_memory_fault fault{};
        const auto readPointer = [&](uint64_t address) {
            uint64_t value = 0;
            REQUIRE(forge_rt_read_guest(instance, thread, token, address, sizeof(value), &value,
                                        sizeof(value), &fault) == FORGE_RT_OK);
            return value;
        };
        const auto environmentCell = readPointer(source);
        const auto environment = readPointer(environmentCell);
        const auto variable = readPointer(environment);
        const auto function = readPointer(source + sizeof(uint64_t));
        REQUIRE(function != 0);
        REQUIRE(forge_rt_validate_guest(instance, thread, token, function, 1, FORGE_RT_READ,
                                        &fault) == FORGE_RT_GUEST_FAULT);
        REQUIRE(fault.address == function && fault.reason == FORGE_RT_FAULT_UNMAPPED);

        const auto output = handle(*execution, stdOutput);
        int32_t success = 0;
        REQUIRE(forge_rt_write_file(instance, thread, output, variable, sizeof("FORGE=retry"),
                                    countSlot, 0, &success, &fault) == FORGE_RT_OK &&
                success == 1);
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, 42, {}, 0};
    }

    void checkRegistrationRetry() {
        const forge_rt_backing storage{16, nullptr, nullptr, 0};
        const forge_rt_region_template slot{source, 16, 0, 0, FORGE_RT_READ};
        const forge_rt_import calls[]{{"kernel32.dll", "GetStdHandle"},
                                      {"kernel32.dll", "WriteFile"},
                                      {"msvcrt.dll", "__getmainargs"}};
        const forge_rt_data_import data{0, FORGE_RT_CRT_INITENV};
        forge_rt_function_import function{8, calls[0]};
        const forge_rt_function_import_artifact descriptor{
            {{{FORGE_RT_FUNCTION_IMPORT_ARTIFACT_VERSION, source, 32, 16, 16, &storage, 1, &slot, 1,
               calls, std::size(calls), writeRegisteredEnvironment},
              "retry.exe"},
             &data,
             1},
            &function,
            1};
        const char *environment[]{"malformed"};
        const forge_rt_process_startup startup{nullptr, 0, nullptr, 1, environment};
        forge_rt_process *raw = nullptr;
        REQUIRE(forge_rt_process_create(FORGE_RT_ABI_VERSION, &raw) == FORGE_RT_OK);
        Process process(raw, forge_rt_process_destroy);
        const auto registerProcess = [&] {
            return forge_rt_process_register_with_startup(process.get(),
                                                          &descriptor.crt.named.artifact, &startup);
        };
        const auto reject = [&] {
            const int reader = captureRegistrationOutput(
                [&] { REQUIRE(registerProcess() == FORGE_RT_INVALID_ARGUMENT); });
            char byte;
            REQUIRE(read(reader, &byte, 1) == 0 && close(reader) == 0);
            forge_rt_process_state state = 0;
            REQUIRE(forge_rt_process_get_state(raw, &state) == FORGE_RT_OK &&
                    state == FORGE_RT_PROCESS_CREATED);
            forge_rt_process_result result{FORGE_RT_RETURNED, FORGE_RT_OK, 17, {}, 0};
            REQUIRE(forge_rt_process_run(raw, nullptr, &result) == FORGE_RT_INVALID_STATE &&
                    result.kind == FORGE_RT_RETURNED && result.value == 17);
        };

        // An invalid environment fails CRT initialization after standard handles are captured.
        reject();

        // An overlapping IAT slot fails after the PE and function addresses have been registered.
        environment[0] = "FORGE=staged";
        function.slotRva = 4;
        reject();

        char variable[] = "FORGE=retry";
        environment[0] = variable;
        function.slotRva = 8;
        const int reader =
            captureRegistrationOutput([&] { REQUIRE(registerProcess() == FORGE_RT_OK); });
        variable[0] = 'X'; // The registered environment owns the copied string.
        REQUIRE(registerProcess() == FORGE_RT_INVALID_STATE);
        REQUIRE(forge_rt_process_register(raw, &descriptor.crt.named.artifact) == FORGE_RT_OK);
        REQUIRE(forge_rt_process_allow_host_output_signals(raw) == FORGE_RT_OK);
        const auto result = run(process);
        REQUIRE(result.kind == FORGE_RT_RETURNED && result.status == FORGE_RT_OK &&
                result.value == 42);
        char bytes[sizeof(variable)];
        REQUIRE(read(reader, bytes, sizeof(bytes)) == sizeof(bytes));
        REQUIRE(std::memcmp(bytes, "FORGE=retry", sizeof(bytes)) == 0);
        REQUIRE(read(reader, bytes, 1) == 0 && close(reader) == 0);
    }

    void expectMissingConsole(forge_rt_instance *instance, forge_rt_thread_token thread) {
        REQUIRE(forge_rt_msvcrt_amsg_exit(instance, thread, 31) == FORGE_RT_INVALID_STATE);
        uint64_t bits = 0xabcd;
        REQUIRE(forge_rt_get_std_handle(instance, thread, stdOutput, &bits) ==
                FORGE_RT_INVALID_STATE);
        REQUIRE(bits == 0xabcd);
        int32_t success = -1;
        forge_rt_memory_fault fault{23, 24, 25};
        REQUIRE(forge_rt_write_file(instance, thread, 0, 1, 1, 2, 0, &success, &fault) ==
                FORGE_RT_INVALID_STATE);
        REQUIRE(success == -1 && fault.address == 23 && fault.access == 24 && fault.reason == 25);
    }

    void runWithoutConsole(forge_rt_execution *execution) {
        REQUIRE(forge_rt_set_last_error(execution->instance, execution->thread, initialError) ==
                FORGE_RT_OK);
        expectMissingConsole(execution->instance, execution->thread);
        REQUIRE(lastError(*execution) == initialError);
        execution->result = {FORGE_RT_RETURNED, FORGE_RT_OK, 17, {}, 0};
    }

    void checkAddressOnlyConsoleImports() {
        const auto checkSlots = [](forge_rt_execution *execution) {
            forge_rt_invocation_token token = 0;
            REQUIRE(forge_rt_current_invocation(execution->instance, execution->thread, &token) ==
                    FORGE_RT_OK);
            uint64_t addresses[3]{};
            forge_rt_memory_fault fault{};
            REQUIRE(forge_rt_read_guest(execution->instance, execution->thread, token, source,
                                        sizeof(addresses), addresses, sizeof(addresses),
                                        &fault) == FORGE_RT_OK);
            REQUIRE(addresses[0] && addresses[1] && addresses[2] && addresses[0] != addresses[1] &&
                    addresses[0] != addresses[2] && addresses[1] != addresses[2]);

            for (const auto address : addresses) {
                REQUIRE(forge_rt_validate_guest(execution->instance, execution->thread, token,
                                                address, 1, FORGE_RT_READ,
                                                &fault) == FORGE_RT_GUEST_FAULT);
                REQUIRE(fault.address == address && fault.reason == FORGE_RT_FAULT_UNMAPPED);
            }

            runWithoutConsole(execution);
        };
        const forge_rt_backing storage{24, nullptr, nullptr, 0};
        const forge_rt_region_template slots{source, 24, 0, 0, FORGE_RT_READ};
        const forge_rt_function_import functions[]{
            {0, imports[0]}, {8, imports[1]}, {16, fatalImport}};
        const forge_rt_function_import_artifact descriptor{
            {{{FORGE_RT_FUNCTION_IMPORT_ARTIFACT_VERSION, source, 32, 24, 24, &storage, 1, &slots,
               1, nullptr, 0, checkSlots},
              "console.exe"},
             nullptr,
             0},
            functions,
            std::size(functions)};
        const auto process = registered(descriptor.crt.named.artifact);
        const auto result = run(process);
        REQUIRE(result.kind == FORGE_RT_RETURNED && result.value == 17);
    }

    void expectCaptureExhaustion(int error) {
        using namespace forge::runtime::darwin;
        std::optional<Descriptor> owner;
        const auto result = Descriptor::capture(STDOUT_FILENO, owner);
        REQUIRE(result.status == CaptureResult::Status::ResourceExhausted && result.error == error);
        REQUIRE(!owner);
    }

    void checkApplicationTypeHeader() {
        using forge::runtime::CrtApplicationType;
        constexpr size_t nt = 64, optional = nt + 24, subsystem = optional + 68;
        std::array<uint8_t, subsystem + 2> header{};
        header[0] = 'M';
        header[1] = 'Z';
        header[0x3c] = nt;
        header[nt] = 'P';
        header[nt + 1] = 'E';
        header[nt + 20] = 70;
        header[optional] = 0x0b;
        header[optional + 1] = 2;
        header[subsystem] = 2;

        forge_rt_backing storage[]{{header.size(), header.data(), nullptr, 0},
                                   {header.size(), nullptr, nullptr, 0}};
        forge_rt_region_template rows[]{{source, header.size(), 0, 0, FORGE_RT_READ},
                                        {source + header.size(), 1, 1, 0, FORGE_RT_READ},
                                        {source + header.size() + 1, 1, 1, 0, FORGE_RT_WRITE}};
        auto artifact = fatalArtifact;
        artifact.size = header.size() + 2;
        artifact.backings = storage;
        artifact.backingCount = std::size(storage);
        artifact.regions = rows;
        artifact.regionCount = 1;
        artifact.entry = [](forge_rt_execution *execution) {
            const auto &windows = *execution->instance->windows;
            const auto &type = windows.appType;
            REQUIRE(windows.standardHandles.has_value() == (type.value != CrtApplicationType::gui));
            execution->result = {
                FORGE_RT_RETURNED, FORGE_RT_OK, static_cast<uint32_t>(type.value), {}, 0};
        };
        const auto selected = [&] { return run(registered(artifact)).value; };
        REQUIRE(selected() == CrtApplicationType::gui);
        header[subsystem] = 3;
        REQUIRE(selected() == CrtApplicationType::console);
        --rows[0].size;
        REQUIRE(selected() == 0);
        ++rows[0].size;
        header[nt + 20] = 68;
        REQUIRE(selected() == 0);
        header[nt + 20] = 70;
        header[0x3f] = 0xff;
        REQUIRE(selected() == 0);
        header[0x3f] = 0;

        // Put every possible field boundary across independently backed immutable rows.
        header[subsystem] = 2;
        std::array<uint8_t, header.size()> prefix{}, tail{};
        storage[0].immutableBytes = prefix.data();
        artifact.regionCount = 2;
        storage[1].immutableBytes = tail.data();
        for (size_t split = 1; split < header.size(); ++split) {
            prefix.fill(0xff);
            std::memcpy(prefix.data(), header.data(), split);
            std::memcpy(tail.data(), header.data() + split, header.size() - split);
            rows[0].size = split;
            rows[1] = {source + split, header.size() - split, 1, 0, FORGE_RT_READ};
            REQUIRE(selected() == CrtApplicationType::gui);
        }

        ++rows[1].start;
        REQUIRE(selected() == 0);
        --rows[1].start;

        // Keep the last byte identical while making its backing privately writable via an alias.
        const forge_rt_fragment fragment{0, 1, tail.data()};
        storage[1] = {1, nullptr, &fragment, 1};
        artifact.regionCount = 3;
        REQUIRE(selected() == 0);

        // A v5 descriptor is authoritative even when a mapped GUI header is present.
        artifact.regionCount = 1;
        storage[0].immutableBytes = header.data();
        rows[0].size = header.size();
        artifact.version = FORGE_RT_PE_ARTIFACT_VERSION;
        forge_rt_pe_artifact pe{{{{artifact, "app.exe"}, nullptr, 0}, nullptr, 0}, 3};
        REQUIRE(run(registered(pe.functions.crt.named.artifact)).value ==
                CrtApplicationType::console);
        pe.subsystem = 0;
        REQUIRE(run(registered(pe.functions.crt.named.artifact)).value == 0);
    }

    void setApplicationTypes(forge_rt_execution *execution) {
        const auto instance = execution->instance;
        const auto thread = execution->thread;
        const auto &windows = *instance->windows;
        using Origin = forge::runtime::CrtApplicationType::Origin;
        REQUIRE(windows.appType.origin == Origin::Default && windows.appType.value == 0);
        REQUIRE(!windows.standardHandles && !windows.crt);
        REQUIRE(forge_rt_msvcrt_set_app_type(instance, 0, 2) == FORGE_RT_INVALID_THREAD);
        REQUIRE(windows.appType.origin == Origin::Default && windows.appType.value == 0);
        REQUIRE(forge_rt_set_last_error(instance, thread, initialError) == FORGE_RT_OK);
        instance->windows->crtErrno = 91;

        for (const int32_t value : {2, 0, INT32_MIN, -7, 1, 2}) {
            REQUIRE(forge_rt_msvcrt_set_app_type(instance, thread, value) == FORGE_RT_OK);
            REQUIRE(windows.appType.value == value && windows.crtErrno == 91);
            REQUIRE(lastError(*execution) == initialError);
        }

        std::thread foreign([&] {
            REQUIRE(forge_rt_msvcrt_set_app_type(instance, thread, 1) ==
                    FORGE_RT_INVALID_INVOCATION);
        });
        foreign.join();
        REQUIRE(windows.appType.value == 2 && !windows.standardHandles);

        REQUIRE(forge_rt_exit_process(instance, thread, 57) == FORGE_RT_OK);
        REQUIRE(forge_rt_msvcrt_set_app_type(instance, thread, 1) == FORGE_RT_INVALID_STATE);
        REQUIRE(windows.appType.value == 2 && execution->result.value == 57);
    }

    void checkApplicationTypeIsolation() {
        constexpr forge_rt_import setter{"msvcrt.dll", "__set_app_type"};
        auto artifact = consoleArtifact(setApplicationTypes);
        artifact.imports = &setter;
        artifact.importCount = 1;
        auto first = registered(artifact);
        auto second = registered(artifact);
        REQUIRE(run(first).value == 57);
        REQUIRE(run(second).value == 57);
        first.reset();
        second.reset();
        REQUIRE(run(registered(artifact)).value == 57);
    }

    void checkNoDescriptorBudget() {
        struct rlimit previous{};
        REQUIRE(getrlimit(RLIMIT_NOFILE, &previous) == 0);
        const struct rlimit none{3, previous.rlim_max};
        REQUIRE(setrlimit(RLIMIT_NOFILE, &none) == 0);
        expectCaptureExhaustion(EINVAL);
        checkAddressOnlyConsoleImports();
        checkApplicationTypeIsolation();
        constexpr forge_rt_import unrelated[]{{"kernel32.dll", "ExitProcess"},
                                              {"kernel32.dll", "GetLastError"},
                                              {"other.dll", "GetStdHandle"},
                                              {"kernel32.dll", "writefile"}};
        auto artifact = consoleArtifact(runWithoutConsole);
        artifact.imports = nullptr;
        artifact.importCount = 0;
        auto empty = registered(artifact);
        REQUIRE(forge_rt_process_allow_host_output_signals(empty.get()) == FORGE_RT_OK);
        REQUIRE(run(empty).value == 17);
        empty.reset();

        artifact.imports = unrelated;
        artifact.importCount = std::size(unrelated);
        auto plain = registered(artifact);
        REQUIRE(run(plain).value == 17);
        plain.reset();

        forge_rt_instance *instance = nullptr;
        forge_rt_thread_token thread = 0;
        forge_rt_invocation_token invocation = 0;
        const forge_rt_image image{source, 16, nullptr, 0};
        REQUIRE(forge_rt_create(FORGE_RT_ABI_VERSION, &instance) == FORGE_RT_OK);
        REQUIRE(forge_rt_thread_create(instance, &thread) == FORGE_RT_OK);
        REQUIRE(forge_rt_enter(instance, thread, &image, nullptr, &invocation) == FORGE_RT_OK);
        REQUIRE(forge_rt_msvcrt_set_app_type(nullptr, thread, 2) == FORGE_RT_INVALID_ARGUMENT);
        REQUIRE(forge_rt_msvcrt_set_app_type(instance, thread, 2) == FORGE_RT_INVALID_STATE);
        expectMissingConsole(instance, thread);
        REQUIRE(forge_rt_leave(instance, thread, invocation) == FORGE_RT_OK);
        REQUIRE(forge_rt_destroy(instance) == FORGE_RT_OK);

        constexpr forge_rt_import console[]{{"KeRneL32.DLL", "WriteFile"},
                                            {"KERNEL32.dll", "GetStdHandle"},
                                            fatalImport,
                                            {"msvcrt.dll", "puts"}};
        artifact = consoleArtifact(finishCapture);
        artifact.importCount = 1;
        forge_rt_process *raw = nullptr;
        REQUIRE(forge_rt_process_create(FORGE_RT_ABI_VERSION, &raw) == FORGE_RT_OK);
        Process retry(raw, forge_rt_process_destroy);

        for (const auto &dependency : console) {
            artifact.imports = &dependency;
            REQUIRE(forge_rt_process_register(raw, &artifact) == FORGE_RT_RESOURCE_EXHAUSTED);
        }

        REQUIRE(setrlimit(RLIMIT_NOFILE, &previous) == 0);
        REQUIRE(forge_rt_process_register(raw, &artifact) == FORGE_RT_OK);
        REQUIRE(run(retry).kind == FORGE_RT_RETURNED);
    }

    void checkFatalCaptureBudget() {
        forge_rt_pe_artifact pe{{{{fatalArtifact, "fatal.exe"}, nullptr, 0}, nullptr, 0}, 2};
        auto &artifact = pe.functions.crt.named.artifact;
        artifact.version = FORGE_RT_PE_ARTIFACT_VERSION;

        struct rlimit previous{};
        REQUIRE(getrlimit(RLIMIT_NOFILE, &previous) == 0);
        const struct rlimit none{3, previous.rlim_max};
        REQUIRE(setrlimit(RLIMIT_NOFILE, &none) == 0);
        expectFatal(registered(artifact), 252);

        const auto checkRetry = [&] {
            forge_rt_process *raw = nullptr;
            REQUIRE(forge_rt_process_create(FORGE_RT_ABI_VERSION, &raw) == FORGE_RT_OK);
            Process retry(raw, forge_rt_process_destroy);
            REQUIRE(forge_rt_process_register(raw, &artifact) == FORGE_RT_RESOURCE_EXHAUSTED);
            REQUIRE(setrlimit(RLIMIT_NOFILE, &previous) == 0);
            REQUIRE(forge_rt_process_register(raw, &artifact) == FORGE_RT_OK);
            expectFatal(retry, 252);
            REQUIRE(setrlimit(RLIMIT_NOFILE, &none) == 0);
        };
        for (const auto subsystem : std::array<uint16_t, 2>{0, 3}) {
            pe.subsystem = subsystem;
            checkRetry();
        }

        pe.subsystem = 2;
        constexpr forge_rt_import dependencies[]{fatalImport, {"kernel32.dll", "WriteFile"}};
        artifact.imports = dependencies;
        artifact.importCount = std::size(dependencies);
        checkRetry();
        REQUIRE(setrlimit(RLIMIT_NOFILE, &previous) == 0);
    }

    void checkCaptureExhaustion() {
        // Leave exactly one new descriptor available. A subsequent duplicate must fail.
        const int first = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
        REQUIRE(first >= 3 && close(first) == 0);
        struct rlimit previous{};
        REQUIRE(getrlimit(RLIMIT_NOFILE, &previous) == 0);
        const struct rlimit one{static_cast<rlim_t>(first + 1), previous.rlim_max};
        REQUIRE(setrlimit(RLIMIT_NOFILE, &one) == 0);
        const int last = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
        REQUIRE(last == first);
        expectCaptureExhaustion(EMFILE);
        REQUIRE(close(last) == 0);
        const auto artifact = consoleArtifact(finishCapture);
        forge_rt_process *raw = nullptr;
        REQUIRE(forge_rt_process_create(FORGE_RT_ABI_VERSION, &raw) == FORGE_RT_OK);
        Process process(raw, forge_rt_process_destroy);
        REQUIRE(forge_rt_process_register(raw, &artifact) == FORGE_RT_RESOURCE_EXHAUSTED);
        REQUIRE(fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3) == first && close(first) == 0);
        REQUIRE(setrlimit(RLIMIT_NOFILE, &previous) == 0);
        REQUIRE(forge_rt_process_register(raw, &artifact) == FORGE_RT_OK);
        REQUIRE(run(process).kind == FORGE_RT_RETURNED);
    }

#ifdef __APPLE__
    void checkNativeCaptureFailure() {
        using namespace forge::runtime::darwin;
        // Darwin opens a descriptor for a named semaphore. It can be duplicated, but
        // fstat on that duplicate fails with EBADF even though the source is available.
        const bool missingInput = fcntl(STDIN_FILENO, F_GETFD) == -1;

        if (missingInput) {
            // Reserve fd 0 so sem_open takes the stdout slot even in a headless host.
            REQUIRE(errno == EBADF && dup2(STDERR_FILENO, STDIN_FILENO) == STDIN_FILENO);
        }

        const int saved = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
        REQUIRE(saved >= 3 && close(STDOUT_FILENO) == 0);
        char name[32];
        std::snprintf(name, sizeof(name), "/forge-capture-%d", getpid());
        auto *semaphore = sem_open(name, O_CREAT | O_EXCL, 0600, 0);
        REQUIRE(semaphore != SEM_FAILED && sem_unlink(name) == 0);

        const int first = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
        REQUIRE(first >= 3 && close(first) == 0);
        std::optional<Descriptor> owner;
        const auto captured = Descriptor::capture(STDOUT_FILENO, owner);
        REQUIRE(captured.status == CaptureResult::Status::NativeFailure && captured.error == EBADF);
        REQUIRE(!owner);
        REQUIRE(fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3) == first && close(first) == 0);

        const auto artifact = consoleArtifact(finishCapture);
        forge_rt_process *raw = nullptr;
        REQUIRE(forge_rt_process_create(FORGE_RT_ABI_VERSION, &raw) == FORGE_RT_OK);
        Process process(raw, forge_rt_process_destroy);
        REQUIRE(forge_rt_process_register(raw, &artifact) == FORGE_RT_HOST_CONFIGURATION);
        REQUIRE(sem_close(semaphore) == 0);
        REQUIRE(dup2(saved, STDOUT_FILENO) == STDOUT_FILENO && close(saved) == 0);

        if (missingInput) {
            REQUIRE(close(STDIN_FILENO) == 0);
        }

        REQUIRE(forge_rt_process_register(raw, &artifact) == FORGE_RT_OK);
        REQUIRE(run(process).kind == FORGE_RT_RETURNED);
    }
#endif

    void checkSignalPolicy(int descriptor, int signal, void (*handler)(int), bool assure,
                           uint32_t expectedError) {
        const auto artifact = consoleArtifact(attemptFailedWrite);
        struct sigaction policy{}, previous{};
        policy.sa_handler = handler;
        REQUIRE(sigemptyset(&policy.sa_mask) == 0);
        REQUIRE(sigaction(signal, &policy, &previous) == 0);
        const int savedOutput = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
        REQUIRE(savedOutput >= 0 && dup2(descriptor, STDOUT_FILENO) == STDOUT_FILENO);
        auto process = registered(artifact);
        REQUIRE(dup2(savedOutput, STDOUT_FILENO) == STDOUT_FILENO && close(savedOutput) == 0);

        if (assure) {
            REQUIRE(forge_rt_process_allow_host_output_signals(process.get()) == FORGE_RT_OK);
        }

        const auto result = run(process);

        if (expectedError) {
            REQUIRE(result.kind == FORGE_RT_RETURNED && result.value == expectedError);
        } else {
            REQUIRE(result.kind == FORGE_RT_RUNTIME_FAILURE &&
                    result.status == FORGE_RT_HOST_CONFIGURATION);
        }

        process.reset();
        struct sigaction observed{};
        REQUIRE(sigaction(signal, &previous, &observed) == 0 && observed.sa_handler == handler);
    }

    void checkPipePolicy(void (*handler)(int), bool descriptorSafe, bool hostAssurance) {
        int ends[2];
        REQUIRE(pipe(ends) == 0 && close(ends[0]) == 0);
#ifdef F_SETNOSIGPIPE
        REQUIRE(fcntl(ends[1], F_SETNOSIGPIPE, static_cast<int>(descriptorSafe)) == 0);
#endif
        const bool safe = descriptorSafe || hostAssurance || handler == SIG_IGN;
        checkSignalPolicy(ends[1], SIGPIPE, handler, hostAssurance, safe ? 109 : 0);
#ifdef F_GETNOSIGPIPE
        REQUIRE(fcntl(ends[1], F_GETNOSIGPIPE) == static_cast<int>(descriptorSafe));
#endif
        REQUIRE(close(ends[1]) == 0);
    }

    void checkClosedSocket() {
        int ends[2];
        REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, ends) == 0 && close(ends[0]) == 0);

        // An inherited signal mask could hide a send that omitted MSG_NOSIGNAL.
        sigset_t signals, previousMask;
        REQUIRE(sigemptyset(&signals) == 0 && sigaddset(&signals, SIGPIPE) == 0);
        REQUIRE(pthread_sigmask(SIG_UNBLOCK, &signals, &previousMask) == 0);
        checkSignalPolicy(ends[1], SIGPIPE, SIG_DFL, false, 109);
        REQUIRE(pthread_sigmask(SIG_SETMASK, &previousMask, nullptr) == 0);
        REQUIRE(close(ends[1]) == 0);
    }

    void checkReadOnlyPipe() {
        int ends[2];
        REQUIRE(pipe(ends) == 0);
        // Handle access fails before the runtime needs a safe host signal policy.
        checkSignalPolicy(ends[0], SIGPIPE, SIG_DFL, false, 5);
        REQUIRE(close(ends[0]) == 0 && close(ends[1]) == 0);
    }

    void checkFileSizePolicy() {
        std::unique_ptr<FILE, decltype(&std::fclose)> file(std::tmpfile(), std::fclose);
        REQUIRE(file != nullptr);
        struct rlimit previous{};
        REQUIRE(getrlimit(RLIMIT_FSIZE, &previous) == 0);
        const struct rlimit limited{0, previous.rlim_max};
        REQUIRE(setrlimit(RLIMIT_FSIZE, &limited) == 0);
        checkSignalPolicy(fileno(file.get()), SIGXFSZ, SIG_DFL, false, 0);
        checkSignalPolicy(fileno(file.get()), SIGXFSZ, SIG_IGN, false, 112);
        checkSignalPolicy(fileno(file.get()), SIGXFSZ, handleOutputSignal, true, 112);
        REQUIRE(setrlimit(RLIMIT_FSIZE, &previous) == 0);
    }
} // namespace

void testRuntimeConsoleProcess(const char *fatalObservations) {
    constexpr std::string_view fatal31 =
        "\r\nruntime error R6031\r\n- Attempt to initialize the CRT more than once.\n"
        "This indicates a bug in your application.\r\n";
    checkFatalProcessIsolation(31, fatal31);
    if (fatalObservations) {
        for (int32_t number = 0; number <= 256; ++number) {
            checkFatalObservation(fatalObservations, number);
        }

        for (const int32_t number : {32767, INT32_MAX, -1, INT32_MIN}) {
            checkFatalObservation(fatalObservations, number);
        }
    }

    checkStreamIdentity();
    checkPutsMemory();
    checkStreamWriteRetries();
    checkStreamTermination();
    checkFatalPartialWrite(31, fatal31);
    checkFatalOutputFailures();
    checkRedirection();
    checkRegistrationRetry();
    checkCaptureCleanup(false);
    checkCaptureCleanup(true);

    for (size_t i = 0; i < std::size(completions); ++i) {
        checkCaptureCleanup(false, i);
    }

    checkApplicationTypeHeader();
    checkNoDescriptorBudget();
    checkFatalCaptureBudget();
    checkCaptureExhaustion();
#ifdef __APPLE__
    checkNativeCaptureFailure();
#endif
    checkReadOnlyPipe();
    checkClosedSocket();
    checkPipePolicy(SIG_DFL, false, false);
    checkPipePolicy(SIG_IGN, false, false);
    checkPipePolicy(handleOutputSignal, false, true);
    checkFileSizePolicy();
#ifdef F_SETNOSIGPIPE
    checkPipePolicy(SIG_DFL, true, false);
#endif
}
