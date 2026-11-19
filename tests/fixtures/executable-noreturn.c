__declspec(dllimport) __declspec(noreturn) void ExitProcess(unsigned int code);

__declspec(noinline) __declspec(noreturn) void terminate(void) { ExitProcess(42); }

void entry(void) { terminate(); }
