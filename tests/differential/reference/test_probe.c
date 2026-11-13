// Integration-only child for inputs and failures outside the permanent corpus.
#define WIN32_LEAN_AND_MEAN
#include <wchar.h>
#include <windows.h>

int wmain(int argc, wchar_t **argv) {
    if (GetEnvironmentVariableW(L"FORGE_TEST_HOST_ONLY", NULL, 0)) {
        return 3;
    }
    if (argc == 1) {
        ExitProcess(0xc0000135UL);
    }
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (wcscmp(argv[1], L"--flood") == 0) {
        char block[8192] = {0};
        DWORD count;
        while (WriteFile(output, block, sizeof(block), &count, NULL)) {
        }
        return 2;
    }
    if (wcscmp(argv[1], L"--sleep") == 0) {
        Sleep(INFINITE);
    }
    for (int i = 1; i < argc; ++i) {
        char utf8[256];
        int length = WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, utf8, sizeof(utf8), NULL, NULL);
        DWORD count;
        if (!length || !WriteFile(output, utf8, (DWORD)length, &count, NULL) ||
            count != (DWORD)length) {
            return 2;
        }
    }
    return 0;
}
