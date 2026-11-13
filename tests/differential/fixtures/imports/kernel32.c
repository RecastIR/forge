#include "streams.h"
#include <windows.h>

int main(void) {
    if (!open_binary_streams()) {
        return 2;
    }
    const int process = GetCurrentProcessId() != 0;
    const int module = GetModuleHandleW(NULL) != NULL;
    const DWORD marker = 0x4152;
    SetLastError(marker);
    const int error = GetLastError() == marker;
    printf("process=%d module=%d last_error=%d\n", process, module, error);
    return process && module && error ? 0 : 1;
}
