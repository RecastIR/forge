#include <stdlib.h>
#include <windows.h>

static void mark(char value) {
    DWORD written;
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &value, 1, &written, NULL) || written != 1) {
        ExitProcess(2);
    }
}

__attribute__((constructor)) static void setup(void) { mark('I'); }

static void first(void) { mark('A'); }

static void second(void) { mark('B'); }

int main(void) {
    if (atexit(first) != 0 || atexit(second) != 0) {
        return 1;
    }

    mark('M');
    return 42;
}
