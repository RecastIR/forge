/* Standalone SDK-free observer. Each command-line case has its own address space. */
typedef unsigned int Dword;
typedef unsigned long long Word;
#define IMPORT __declspec(dllimport)
IMPORT int VirtualProtect(void *, Word, Dword, Dword *);
IMPORT void *VirtualAlloc(void *, Word, Dword, Dword);
IMPORT int VirtualFree(void *, Word, Dword);
IMPORT Word VirtualQuery(const void *, void *, Word);
IMPORT char *GetCommandLineA(void);
IMPORT void GetSystemInfo(void *);
IMPORT void SetLastError(Dword);
IMPORT Dword GetLastError(void);
IMPORT void *GetStdHandle(int);
IMPORT int WriteFile(void *, const void *, Dword, Dword *, void *);

static __declspec(align(4096)) unsigned char data[8192] = {42};
static const Dword immutable = 0x11223344;

static Dword protection(const void *page) {
    struct {
        Word base, allocation;
        Dword initial, pad;
        Word size;
        Dword state, protect, type, padding;
    } info;

    return VirtualQuery(page, &info, sizeof(info)) == sizeof(info) ? info.protect : 0xffffffff;
}

int entry(void) {
    char *arg = GetCommandLineA();
    while (*arg) {
        ++arg;
    }
    unsigned int test = (arg[-2] - '0') * 10 + arg[-1] - '0';
    unsigned char *target = data;
    Word length = 1;
    Dword mode = 2, old = 0x11223344, *out = &old;
    Dword sys[16], written;
    GetSystemInfo(sys);
    if (test != 0 && test != 30 && test != 31 && test != 42) {
        data[0] = 19;
    }
    switch (test) {
    case 0:
    case 1:
        break;
    case 2:
        length = 0;
        break;
    case 3:
        ++target;
        length = 0;
        break;
    case 4:
        target = 0;
        break;
    case 5:
        target = (void *)1;
        break;
    case 6:
        target = (void *)-2LL;
        length = 4;
        break;
    case 7:
        mode = 3;
        break;
    case 8:
        mode = 0x102;
        break;
    case 9:
        mode = 0x101;
        break;
    case 10:
        out = 0;
        break;
    case 11:
        out = (void *)1;
        break;
    case 12:
        out = (Dword *)&immutable;
        break;
    case 13:
        out = (Dword *)(data + 8);
        break;
    case 14:
        out = (Dword *)(data + 8);
        mode = 4;
        break;
    case 15:
        target += 4095;
        length = 2;
        break;
    case 16:
    case 17:
        target = VirtualAlloc(0, 8192, 0x2000, 4);
        if (!target || VirtualAlloc(target, 4096, 0x1000, 4) != target) {
            return 98;
        }
        length = test == 16 ? 8192 : 4096;
        break;
    case 18: {
        target = VirtualAlloc(0, 131072, 0x2000, 4);
        if (!target || !VirtualFree(target, 0, 0x8000) ||
            VirtualAlloc(target, 65536, 0x3000, 4) != target ||
            VirtualAlloc(target + 65536, 65536, 0x3000, 4) != target + 65536) {
            return 98;
        }
        target += 65535;
        length = 2;
        break;
    }
    case 19:
        mode = 8;
        break;
    case 20:
        mode = 0x202;
        break;
    case 21:
        mode = 0x40;
        break;
    case 22:
        mode = 0x402;
        break;
    case 23:
        mode = 0x20000000;
        break;
    case 24:
        out = (Dword *)(data + 4094);
        target += 4096;
        break;
    case 25:
        target = (void *)&entry;
        mode = 0x40;
        break;
    case 26:
        target = (void *)&immutable;
        mode = 4;
        break;
    case 27:
        target = (void *)0x10000;
        length = (Word)-1;
        break;
    case 28:
        mode = 0x40000004;
        break;
    case 29:
        mode = 0;
        break;
    case 30:
        mode = 4;
        break;
    case 31:
    case 32:
        if (!VirtualProtect(target, 1, 2, &old)) {
            return 98;
        }
        old = 0x11223344;
        mode = 4;
        break;
    case 33:
        target = (void *)0xffffffffffffffffULL;
        break;
    case 34:
        mode = 0x20000002;
        break;
    case 35:
        out = (Dword *)(data + 4097);
        break;
    case 36:
        out = 0;
        length = 0;
        break;
    case 37:
        out = (void *)1;
        mode = 0;
        break;
    case 38:
        out = (void *)1;
        target = 0;
        break;
    case 39:
        target = (void *)0x0000800000000000ULL;
        break;
    case 40:
        if (!VirtualProtect(target, 1, 2, &old)) {
            return 98;
        }
        out = (Dword *)(data + 8);
        mode = 4;
        break;
    case 41:
        mode = 0x80000002;
        break;
    case 42:
        out = (Dword *)(data + 8);
        mode = 4;
        break;
    case 43:
        out = (Dword *)(data + 4096);
        break;
    case 44:
        out = (Dword *)(data + 4096);
        length = 0;
        break;
    default:
        return 99;
    }
    Dword before = protection(target);
    SetLastError(73);
    int result = VirtualProtect(target, length, mode, out);
    Dword error = GetLastError();
    Dword observed = out == &old ? old
                                 : (result && (test == 13 || test == 14 || test == 24 ||
                                               test == 35 || test == 40 || test == 42 || test == 43)
                                        ? *out
                                        : old);
    Dword record[] = {sys[1],
                      before,
                      (Dword)result,
                      observed,
                      error,
                      protection(target),
                      protection(data + 4096)};
    if (test == 44) {
        // Capture the untouched or published DWORD before probing its page a second time.
        record[3] = *out;
        if (!VirtualProtect(out, 1, 2, &record[6])) {
            return 98;
        }
    }
    return WriteFile(GetStdHandle(-11), record, sizeof(record), &written, 0) &&
                   written == sizeof(record)
               ? 42
               : 97;
}
