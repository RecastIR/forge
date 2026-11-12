// Run one console PE. The Wine launcher's Unix status only describes this helper.
#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

struct stream {
    HANDLE input;
    HANDLE child;
    const char* filename;
    size_t limit;
};

static void win_error(const char* operation) {
    DWORD error = GetLastError();
    fprintf(stderr, "%s failed (Win32 %lu)\n", operation, error);
    ExitProcess(1);
}

static void capture_error(const char* message, const char* file) {
    fprintf(stderr, "%s: %s\n", message, file);
    ExitProcess(1);
}

static HANDLE open_stream(struct stream* stream, SECURITY_ATTRIBUTES* inherit) {
    if (!CreatePipe(&stream->input, &stream->child, inherit, 0) ||
        !SetHandleInformation(stream->input, HANDLE_FLAG_INHERIT, 0)) {
        win_error("create stream pipe");
    }
    return stream->child;
}

static DWORD WINAPI drain(void* arg) {
    struct stream* stream = arg;
    FILE* out = fopen(stream->filename, "wb");
    if (!out) {
        capture_error("cannot open capture", stream->filename);
    }
    unsigned char bytes[8192];
    size_t total = 0;
    for (;;) {
        DWORD count = 0;
        if (!ReadFile(stream->input, bytes, sizeof(bytes), &count, NULL)) {
            if (GetLastError() == ERROR_BROKEN_PIPE) {
                break;
            }
            win_error("read fixture pipe");
        }
        if (count > stream->limit - total) {
            capture_error("output-size limit exceeded", stream->filename);
        }
        if (fwrite(bytes, 1, count, out) != count) {
            capture_error("cannot write capture", stream->filename);
        }
        total += count;
    }
    if (fclose(out) != 0) {
        capture_error("cannot finish capture", stream->filename);
    }
    CloseHandle(stream->input);
    return 0;
}

static void record(const char* filename, const void* data, size_t length) {
    FILE* file = fopen(filename, "wb");
    if (!file || fwrite(data, 1, length, file) != length || fclose(file) != 0) {
        capture_error("cannot write capture record", filename);
    }
}

static void loader_failure(DWORD status) {
    const char* category = (status == 0xc0000135 || status == ERROR_MOD_NOT_FOUND)
                               ? "missing Windows runtime dependency"
                               : "Windows loader startup failure";
    fprintf(stderr, "%s (0x%08lx)\n", category, status);
    ExitProcess(1);
}

// Wine 8 raises ntdll!DbgBreakPoint after resolving imports and initializing DLLs.
// A process that dies before this point has no observed program exit status.
static void wait_for_loader(PROCESS_INFORMATION* process) {
    FARPROC breakpoint = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "DbgBreakPoint");
    if (!breakpoint) {
        win_error("locate loader breakpoint");
    }
    for (;;) {
        DEBUG_EVENT event;
        if (!WaitForDebugEvent(&event, INFINITE)) {
            win_error("wait for loader");
        }
        DWORD disposition = DBG_CONTINUE;
        BOOL ready = FALSE;
        switch (event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            if (event.u.CreateProcessInfo.hFile) {
                CloseHandle(event.u.CreateProcessInfo.hFile);
            }
            break;
        case LOAD_DLL_DEBUG_EVENT:
            if (event.u.LoadDll.hFile) {
                CloseHandle(event.u.LoadDll.hFile);
            }
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            loader_failure(event.u.ExitProcess.dwExitCode);
            break;
        case EXCEPTION_DEBUG_EVENT: {
            const EXCEPTION_DEBUG_INFO* info = &event.u.Exception;
            ready = info->dwFirstChance && event.dwThreadId == process->dwThreadId &&
                    info->ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT &&
                    info->ExceptionRecord.ExceptionAddress == (void*)breakpoint;
            disposition = ready ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
            break;
        }
        }
        // Keep the initial thread stopped across ContinueDebugEvent and debugger detach.
        if (ready && SuspendThread(process->hThread) == (DWORD)-1) {
            win_error("suspend initial thread");
        }
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition)) {
            win_error("continue loader");
        }
        if (ready) {
            if (!DebugActiveProcessStop(process->dwProcessId)) {
                win_error("detach loader observer");
            }
            record("ready", "", 0);
            if (ResumeThread(process->hThread) == (DWORD)-1) {
                win_error("resume initial thread");
            }
            return;
        }
    }
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) {
        return 1;
    }
    // The guest supervisor has already quoted the argv vector as UTF-16LE.
    static wchar_t command[32768];
    FILE* input = fopen("command.bin", "rb");
    if (!input) {
        capture_error("cannot open command", "command.bin");
    }
    size_t length = fread(command, sizeof(wchar_t), 32768, input);
    if (!feof(input) || !length || length >= 32768 || fclose(input) != 0) {
        capture_error("invalid Windows command line", "command.bin");
    }
    size_t limit = wcstoul(argv[2], NULL, 10);
    struct stream streams[2] = {{NULL, NULL, "stdout.bin", limit},
                                {NULL, NULL, "stderr.bin", limit}};
    SECURITY_ATTRIBUTES inherit = {sizeof(inherit), NULL, TRUE};
    STARTUPINFOW startup = {0};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    &inherit, OPEN_EXISTING, 0, NULL);
    if (startup.hStdInput == INVALID_HANDLE_VALUE) {
        win_error("open fixture stdin");
    }
    startup.hStdOutput = open_stream(&streams[0], &inherit);
    startup.hStdError = open_stream(&streams[1], &inherit);
    PROCESS_INFORMATION process;
    if (!CreateProcessW(argv[1], command, NULL, NULL, TRUE, DEBUG_ONLY_THIS_PROCESS, NULL,
                        L"C:\\work", &startup, &process)) {
        loader_failure(GetLastError());
    }
    CloseHandle(startup.hStdInput);
    HANDLE wait_for[3] = {process.hProcess, NULL, NULL};
    for (int i = 0; i < 2; ++i) {
        CloseHandle(streams[i].child);
        wait_for[i + 1] = CreateThread(NULL, 0, drain, &streams[i], 0, NULL);
        if (!wait_for[i + 1]) {
            win_error("start capture reader");
        }
    }
    wait_for_loader(&process);
    if (WaitForMultipleObjects(3, wait_for, TRUE, INFINITE) != WAIT_OBJECT_0) {
        win_error("wait for fixture and streams");
    }
    DWORD status;
    if (!GetExitCodeProcess(process.hProcess, &status)) {
        win_error("read fixture exit code");
    }
    record("exit.bin", &status, sizeof(status));
    return 0;
}
