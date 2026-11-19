// Reference observer for bounded, repository-owned console probes on Windows and Wine.
#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static void fail(const char *operation) {
    DWORD error = GetLastError();
    fprintf(stderr, "%s failed %lu\n", operation, error);
    exit(2);
}

static void path(char *destination, const char *directory, const char *name) {
    if (snprintf(destination, MAX_PATH, "%s\\%s", directory, name) >= MAX_PATH) {
        exit(2);
    }
}

static FILE *output(const char *directory, const char *name) {
    char filename[MAX_PATH];
    path(filename, directory, name);
    FILE *stream = fopen(filename, "wb");
    if (!stream) {
        fail("fopen");
    }
    return stream;
}

static HANDLE screen(DWORD access, SECURITY_ATTRIBUTES *inherit) {
    return CreateFileW(L"CONOUT$", access, FILE_SHARE_READ | FILE_SHARE_WRITE, inherit,
                       OPEN_EXISTING, 0, NULL);
}

static void snapshot(const char *directory, const char *name, FILE *meta) {
    HANDLE console = screen(GENERIC_READ | GENERIC_WRITE, NULL);
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (console == INVALID_HANDLE_VALUE || !GetConsoleScreenBufferInfo(console, &info)) {
        fail("GetConsoleScreenBufferInfo");
    }
    fprintf(meta, "%s size=%d,%d cursor=%d,%d\n", name, info.dwSize.X, info.dwSize.Y,
            info.dwCursorPosition.X, info.dwCursorPosition.Y);
    FILE *file = output(directory, name);
    // Store the first twelve complete screen rows, as native UTF-16LE cells.
    DWORD count = (DWORD)info.dwSize.X * (info.dwSize.Y < 12 ? info.dwSize.Y : 12);
    WCHAR *cells = calloc(count, sizeof(*cells));
    DWORD n;
    if (!cells || !ReadConsoleOutputCharacterW(console, cells, count, (COORD){0, 0}, &n) ||
        n != count || fwrite(cells, sizeof(*cells), n, file) != n || fclose(file) != 0) {
        fail("ReadConsoleOutputCharacterW");
    }
    free(cells);
    CloseHandle(console);
}

static void capture_pipe(HANDLE input, const char *directory, const char *name) {
    FILE *file = output(directory, name);
    char data[512];
    DWORD n;
    for (;;) {
        if (!ReadFile(input, data, sizeof(data), &n, NULL)) {
            if (GetLastError() != ERROR_BROKEN_PIPE) {
                fail("ReadFile(pipe)");
            }
            break;
        }
        if (n == 0) {
            break;
        }
        if (fwrite(data, 1, n, file) != n) {
            fail("fwrite(pipe)");
        }
    }
    if (fclose(file) != 0) {
        fail("fclose(pipe)");
    }
    CloseHandle(input);
}

static int marker(void) {
    static const char text[] = "CONOUT control!";
    HANDLE console = screen(GENERIC_WRITE, NULL);
    DWORD written = 0;
    BOOL ok = WriteConsoleA(console, text, sizeof(text) - 1, &written, NULL);
    CloseHandle(console);
    return (ok && written == sizeof(text) - 1) ? 77 : 78;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--marker")) {
        return marker();
    }
    if (argc == 3 && !strcmp(argv[1], "--error")) {
        // Additional error IDs go to the installed DLL on this machine.
        HMODULE crt = GetModuleHandleA("msvcrt.dll");
        void(__cdecl * fatal)(int) =
            (void(__cdecl *)(int))(void *)GetProcAddress(crt, "_amsg_exit");
        if (!fatal) {
            fail("GetProcAddress");
        }
        fatal(atoi(argv[2]));
        return 42;
    }
    if (argc < 4 || argc > 6) {
        return 2;
    }
    const char *program = argv[1], *mode = argv[2], *directory = argv[3];
    // Wine's Unix terminal presents a stream, whereas AllocConsole on Windows exposes cells.
    int terminal = !strcmp(mode, "terminal") || !strcmp(mode, "terminal-pipe");
    int attached = terminal || !strcmp(mode, "console") || !strcmp(mode, "console-pipe");
    int broken = !strcmp(mode, "broken-pipe");
    int pipes =
        !strcmp(mode, "pipe") || !strcmp(mode, "console-pipe") || !strcmp(mode, "terminal-pipe");
    int files = !strcmp(mode, "file");
    if (!attached && !pipes && !broken && !files && strcmp(mode, "invalid")) {
        return 2;
    }
    if (!CreateDirectoryA(directory, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        fail("CreateDirectory");
    }
    FILE *meta = output(directory, "observation.txt");
    if (attached && !terminal) {
        FreeConsole();
        if (!AllocConsole()) {
            fail("AllocConsole");
        }
        HANDLE console = screen(GENERIC_READ | GENERIC_WRITE, NULL);
        if (console == INVALID_HANDLE_VALUE || !SetConsoleCursorPosition(console, (COORD){0, 0})) {
            fail("SetConsoleCursorPosition");
        }
        CloseHandle(console);
        snapshot(directory, "before.utf16le", meta);
    }
    SECURITY_ATTRIBUTES inherit = {sizeof(inherit), NULL, TRUE};
    STARTUPINFOA startup = {0};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    &inherit, OPEN_EXISTING, 0, NULL);
    if (startup.hStdInput == INVALID_HANDLE_VALUE) {
        fail("open NUL");
    }
    HANDLE child[2], readers[2] = {NULL, NULL};
    const char *streams[] = {"stdout.bin", "stderr.bin"};
    for (int i = 0; i < 2; ++i) {
        if (pipes || broken) {
            if (!CreatePipe(&readers[i], &child[i], &inherit, 0) ||
                !SetHandleInformation(readers[i], HANDLE_FLAG_INHERIT, 0)) {
                fail("CreatePipe");
            }
            if (broken) {
                CloseHandle(readers[i]);
            }
        } else if (files) {
            char name[MAX_PATH];
            path(name, directory, streams[i]);
            child[i] = CreateFileA(name, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   &inherit, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (child[i] == INVALID_HANDLE_VALUE) {
                fail("CreateFile(stream)");
            }
        } else if (attached) {
            child[i] = screen(GENERIC_WRITE, &inherit);
            if (child[i] == INVALID_HANDLE_VALUE) {
                fail("open CONOUT$");
            }
        } else {
            child[i] = INVALID_HANDLE_VALUE;
        }
    }
    startup.hStdOutput = child[0];
    startup.hStdError = child[1];
    PROCESS_INFORMATION process = {0};
    char command[2 * MAX_PATH];
    if (snprintf(command, sizeof(command), "\"%s\" %s %s", program, argc > 4 ? argv[4] : "",
                 argc > 5 ? argv[5] : "") >= (int)sizeof(command)) {
        return 2;
    }
    if (!CreateProcessA(program, command, NULL, NULL, TRUE, attached ? 0 : DETACHED_PROCESS, NULL,
                        NULL, &startup, &process)) {
        fail("CreateProcess");
    }
    for (int i = 0; i < 2; ++i) {
        if (child[i] != INVALID_HANDLE_VALUE) {
            CloseHandle(child[i]);
        }
    }
    CloseHandle(startup.hStdInput);
    CloseHandle(process.hThread);
    DWORD status;
    if (WaitForSingleObject(process.hProcess, 12000) != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 0xf0);
        fail("child did not terminate");
    }
    if (!GetExitCodeProcess(process.hProcess, &status)) {
        fail("GetExitCodeProcess");
    }
    CloseHandle(process.hProcess);
    fprintf(meta, "exit=%lu\n", status);
    if (pipes) {
        for (int i = 0; i < 2; ++i) {
            capture_pipe(readers[i], directory, streams[i]);
        }
    }
    if (attached && !terminal) {
        snapshot(directory, "after.utf16le", meta);
    }
    return fclose(meta) != 0;
}
