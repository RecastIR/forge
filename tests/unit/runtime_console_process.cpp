#include "../../runtime/src/platform/darwin/io.h"
#include <forge/process.h>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iterator>
#include <memory>
#include <optional>
#include <pthread.h>
#ifdef __APPLE__
#include <semaphore.h>
#endif
#include <sys/resource.h>
#include <sys/socket.h>
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
            uint64_t addresses[2]{};
            forge_rt_memory_fault fault{};
            REQUIRE(forge_rt_read_guest(execution->instance, execution->thread, token, source,
                                        sizeof(addresses), addresses, sizeof(addresses),
                                        &fault) == FORGE_RT_OK);
            REQUIRE(addresses[0] && addresses[1] && addresses[0] != addresses[1]);

            for (const auto address : addresses) {
                REQUIRE(forge_rt_validate_guest(execution->instance, execution->thread, token,
                                                address, 1, FORGE_RT_READ,
                                                &fault) == FORGE_RT_GUEST_FAULT);
                REQUIRE(fault.address == address && fault.reason == FORGE_RT_FAULT_UNMAPPED);
            }

            runWithoutConsole(execution);
        };
        const forge_rt_backing storage{16, nullptr, nullptr, 0};
        const forge_rt_region_template slots{source, 16, 0, 0, FORGE_RT_READ};
        const forge_rt_function_import functions[]{{0, imports[0]}, {8, imports[1]}};
        const forge_rt_function_import_artifact descriptor{
            {{{FORGE_RT_FUNCTION_IMPORT_ARTIFACT_VERSION, source, 32, 16, 16, &storage, 1, &slots,
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

    void checkNoDescriptorBudget() {
        struct rlimit previous{};
        REQUIRE(getrlimit(RLIMIT_NOFILE, &previous) == 0);
        const struct rlimit none{3, previous.rlim_max};
        REQUIRE(setrlimit(RLIMIT_NOFILE, &none) == 0);
        expectCaptureExhaustion(EINVAL);
        checkAddressOnlyConsoleImports();
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
        expectMissingConsole(instance, thread);
        REQUIRE(forge_rt_leave(instance, thread, invocation) == FORGE_RT_OK);
        REQUIRE(forge_rt_destroy(instance) == FORGE_RT_OK);

        constexpr forge_rt_import console[]{{"KeRneL32.DLL", "WriteFile"},
                                            {"KERNEL32.dll", "GetStdHandle"}};
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

void testRuntimeConsoleProcess() {
    checkRedirection();
    checkRegistrationRetry();
    checkCaptureCleanup(false);
    checkCaptureCleanup(true);

    for (size_t i = 0; i < std::size(completions); ++i) {
        checkCaptureCleanup(false, i);
    }

    checkNoDescriptorBudget();
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
