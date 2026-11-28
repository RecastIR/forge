/* SDK-free PE. Every case runs in a fresh process. The Windows observer also
 * checks these field offsets against the installed x64 Windows SDK. */
typedef unsigned int Dword;
typedef unsigned long long Word;
typedef unsigned char Byte;
#define IMPORT __declspec(dllimport)
IMPORT Word VirtualQuery(const void *, void *, Word);
IMPORT int VirtualProtect(void *, Word, Dword, Dword *);
IMPORT void *VirtualAlloc(void *, Word, Dword, Dword);
IMPORT int VirtualFree(void *, Word, Dword);
IMPORT void SetLastError(Dword);
IMPORT Dword GetLastError(void);
IMPORT char *GetCommandLineA(void);
IMPORT void *GetStdHandle(int);
IMPORT int WriteFile(void *, const void *, Dword, Dword *, void *);
extern Byte __ImageBase;

static __declspec(align(4096)) Byte image[8192] = {0x71};
static const Byte immutable[64] = {0x31};

struct Record {
    Dword marker, error;
    Word returned, base, query, length;
    Byte bytes[64]; /* Eight bytes on each side of the result. */
    Word output;
};
_Static_assert(sizeof(struct Record) == 112, "capture record");

static int measure(unsigned id, Byte *target, Byte *out, Word length, const Byte *window) {
    struct Record record;
    record.marker = 0x51a70000 + id;
    record.base = (Word)&__ImageBase;
    record.query = (Word)target;
    record.length = length;
    record.output = (Word)out;
    SetLastError(73);
    record.returned = VirtualQuery(target, out, length);
    record.error = GetLastError();
    for (unsigned i = 0; i < sizeof(record.bytes); ++i) {
        record.bytes[i] = window ? window[i] : 0;
    }
    Dword written = 0;
    return WriteFile(GetStdHandle(-11), &record, sizeof(record), &written, 0) &&
           written == sizeof(record);
}

int entry(void) {
    const char *end = GetCommandLineA();
    while (*end) {
        ++end;
    }
    unsigned test = (end[-2] - '0') * 10 + end[-1] - '0';
    Byte local[80];
    for (unsigned i = 0; i < sizeof(local); ++i) {
        local[i] = 0xa5;
    }
    Word length = 48;
    Byte *target = image, *out = local + 8;
    const Byte *window = local;
    Byte *alloc = 0;
    Dword old;
    switch (test) {
    case 0: target = 0; break;
    case 1: target = (Byte *)1; break;
    case 2: target = (Byte *)65535; break;
    case 3: target = (Byte *)0x800000000000ULL; break;
    case 4: target = (Byte *)-1LL; break;
    case 5: case 6: case 7:
        out = 0;
        window = 0;
        if (test == 6) length = 47;
        if (test == 7) target = (Byte *)-1LL;
        break;
    case 8: case 9:
        out = (Byte *)immutable + 8;
        window = immutable;
        if (test == 9) length = 0;
        break;
    case 10: case 11: case 12: case 13: case 14:
        window = image + 64;
        out = image + 72;
        if (test == 11) target = image + 4096;
        if (test == 12) target = (Byte *)-1LL;
        if (test == 13) length = 47;
        if (test == 14) length = 0x10000002fULL;
        break;
    case 15: case 16: case 17: case 18:
        alloc = VirtualAlloc(0, 8192, 0x3000, 4);
        if (!alloc) return 96;
        for (unsigned i = 0; i < 96; ++i) alloc[4096 - 64 + i] = 0x73;
        if (!VirtualProtect(alloc + 4096, 4096, 2, &old)) return 97;
        out = alloc + 4096 - (test == 15 ? 48 : 47);
        window = out - 8;
        if (test == 17) length = 47;
        if (test == 18) target = (Byte *)-1LL;
        break;
    case 19: target = (Byte *)-1LL; length = 0; break;
    case 20: target = (Byte *)-1LL; length = 0x100000000ULL; break;
    case 21: target = (Byte *)0x7fffffff0000ULL; break;
    case 22: target = (Byte *)0x7ffffffeffffULL; break;
    default: return 95;
    }
    if (!measure(100 + test, target, out, length, window)) return 98;
    if (test >= 10 && test <= 14 &&
        !measure(200 + test, image, local + 8, 48, local)) return 98;
    if (alloc && !VirtualFree(alloc, 0, 0x8000)) return 99;
    return 42;
}
