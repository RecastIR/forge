/* SDK-free observer of the system msvcrt.dll. Each invocation starts with fresh streams. */
typedef unsigned int Dword;
typedef unsigned long long Word;

typedef struct {
    char *ptr;
    int cnt;
    char *base;
    int flag, file, charbuf, bufsiz;
    char *tmpfname;
} File;

_Static_assert(sizeof(File) == 48 && _Alignof(File) == 8, "legacy x64 FILE");
#define IMPORT __declspec(dllimport)
IMPORT File *__iob_func(void);
IMPORT Word fwrite(const void *, Word, Word, File *);
IMPORT int *_errno(void);
IMPORT void _cexit(void);
IMPORT void exit(int);
IMPORT void _amsg_exit(int);
IMPORT char *GetCommandLineA(void);
IMPORT void *GetStdHandle(int);
IMPORT int WriteFile(void *, const void *, Dword, Dword *, void *);
IMPORT void SetLastError(Dword);
IMPORT Dword GetLastError(void);
IMPORT void ExitProcess(Dword);
IMPORT int CloseHandle(void *);

static char data[8193] = {'A', 0, '\n', '\r', '\n', 'Z'};

static void raw(void *handle, const void *data, Dword len) {
    Dword written;
    WriteFile(handle, data, len, &written, 0);
}

/* Store pointer relationships, which survive ASLR, and every legacy scalar field. */
static void snapshot(void *log, File *f, Word result, int error, Dword last) {
    Word row[] = {result,
                  (unsigned)error,
                  last,
                  f->ptr != 0,
                  f->base != 0,
                  (Word)f->ptr - (Word)f->base,
                  (unsigned)f->cnt,
                  (unsigned)f->flag,
                  (unsigned)f->file,
                  (unsigned)f->charbuf,
                  (unsigned)f->bufsiz,
                  f->tmpfname != 0};
    raw(log, row, sizeof(row));
}

int entry(void) {
    char *end = GetCommandLineA();
    while (*end) {
        ++end;
    }
    unsigned test = (end[-2] - '0') * 10 + end[-1] - '0';
    unsigned index = test & 1 ? 2 : 1;
    unsigned mode = test / 2;
    void *out = GetStdHandle(-10 - (int)index);
    void *log = GetStdHandle(index == 2 ? -11 : -12);
    int *error = _errno();
    File *base = __iob_func();
    File *stream = base + index;
    if (base != __iob_func() || ((Word)base & 7)) {
        return 9;
    }
    for (unsigned i = 0; i < 3; ++i) {
        snapshot(log, base + i, 0, 0, 0);
    }
    Word size = 2, count = 3;
    const void *src = data;
    switch (mode) {
    case 1:
        size = 0;
        src = 0;
        break;
    case 2:
        count = 0;
        src = 0;
        break;
    case 3:
        size = (Word)1 << 63;
        count = 2;
        break;
    case 4:
        size = ((Word)1 << 63) + 1;
        count = 2;
        break;
    case 5:
        size = 1;
        count = 4095;
        break;
    case 6:
        size = 1;
        count = 4096;
        break;
    case 7:
        size = 1;
        count = 4097;
        break;
    case 8:
        size = 2;
        count = 4096;
        break;
    case 9:
        stream = base;
        break;
    case 10:
        CloseHandle(out);
        break;
    case 11:
        CloseHandle(out);
        size = 2;
        count = 4096;
        break;
    case 12:
        size = 0;
        src = 0;
        stream = 0;
        break;
    case 13:
        stream = (File *)1;
        break;
    case 14:
        src = (void *)1;
        break;
    case 15:
        break; /* Win32 process exit */
    case 16:
        break; /* CRT exit */
    case 17:
        break; /* DLL detach following an outer return */
    case 18:
        break; /* Fatal diagnostic and DLL detach */
    case 19:
        src = 0;
        break;
    case 20:
        stream = 0;
        break;
    case 21:
        stream = base;
        src = (void *)1;
        break;
    case 22:
        stream = base;
        size = 1;
        count = 4096;
        break;
    case 23:
        stream = (File *)1;
        count = 0;
        break;
    }
    *error = 37;
    SetLastError(91);
    Word result = fwrite(src, size, count, stream);
    Dword last = GetLastError();
    snapshot(log, (stream == base ? base : base + index), result, *error, last);
    raw(out, "#", 1);
    if (mode == 15) {
        ExitProcess(42);
    }
    if (mode == 16) {
        exit(42);
    }
    if (mode == 17) {
        return 42;
    }
    if (mode == 18) {
        _amsg_exit(8);
    }
    _cexit();
    last = GetLastError();
    snapshot(log, (stream == base ? base : base + index), 0, *error, last);
    raw(out, "|", 1);
    return 42;
}
