/* SDK-free reference-only measurements of the system DLL. */
typedef unsigned long DWORD;
typedef unsigned long long Word;
typedef void *Handle;
typedef struct Stream Stream;
#define IMPORT __declspec(dllimport)
IMPORT void GetStartupInfoA(void *);
IMPORT void GetStartupInfoW(void *);
IMPORT Handle GetStdHandle(DWORD);
IMPORT int SetStdHandle(DWORD, Handle);
IMPORT DWORD GetLastError(void);
IMPORT void SetLastError(DWORD);
IMPORT DWORD GetFileType(Handle);
IMPORT DWORD GetFileSize(Handle, DWORD *);
IMPORT void ExitProcess(DWORD);
IMPORT int *_errno(void);
typedef int (*Handler)(void);
IMPORT Handler _onexit(Handler);
IMPORT void _cexit(void);
IMPORT void exit(int);
IMPORT Stream *fopen(const char *, const char *);
IMPORT int fclose(Stream *);
IMPORT int fputc(int, Stream *);
IMPORT int setvbuf(Stream *, char *, int, Word);
IMPORT int _fileno(Stream *);
IMPORT Word _get_osfhandle(int);
IMPORT Word fwrite(const void *, Word, Word, Stream *);

static void record(const void *data, Word size) {
    Stream *out = fopen("record.bin", "ab");
    if (!out || fwrite(data, 1, size, out) != size || fclose(out)) {
        ExitProcess(111);
    }
}

#if defined(STARTUP)
typedef union {
    unsigned char bytes[104];
    Word words[13];
} Startup;

int entry(void) {
    Handle original[3];
    for (int i = 0; i < 3; ++i) {
        original[i] = GetStdHandle(-10 - i);
    }

    for (int pass = 0; pass < 2; ++pass) {
        if (pass && !SetStdHandle(-11, original[2])) {
            return 1;
        }

        for (int wide = 0; wide < 2; ++wide) {
            Startup info;
            for (int i = 0; i < 104; ++i) {
                info.bytes[i] = 0xbc;
            }

            SetLastError(91);
            if (wide) {
                GetStartupInfoW(&info);
            } else {
                GetStartupInfoA(&info);
            }

            DWORD error = GetLastError();
            record(&info, sizeof(info));
            record(original, sizeof(original));
            record(&error, sizeof(error));
            /* Record creation strings by value, including the terminator when it fits. */
            for (int field = 1; field <= 3; ++field) {
                unsigned short text[260] = {0};
                if (info.words[field]) {
                    for (unsigned int i = 0; i < 260; ++i) {
                        text[i] = wide ? ((const unsigned short *)info.words[field])[i]
                                       : ((const unsigned char *)info.words[field])[i];
                        if (!text[i]) {
                            break;
                        }
                    }
                }

                record(text, sizeof(text));
            }
        }
    }
    return 42;
}
#elif defined(STREAM) || defined(STREAM_EXIT)
static char buffer[4096];

int entry(void) {
    Stream *file = fopen("buffered.bin", "wb");
    if (!file || setvbuf(file, buffer, 0, sizeof(buffer)) || fputc('X', file) != 'X') {
        return 1;
    }
    Handle handle = (Handle)_get_osfhandle(_fileno(file));
    DWORD before = GetFileSize(handle, 0);
    record(&before, sizeof(before));
#ifdef STREAM_EXIT
    exit(42);
#else
    _cexit();
    DWORD after[] = {GetFileType(handle), GetFileSize(handle, 0)};
    record(after, sizeof(after));
    ExitProcess(42);
#endif
    return 1;
}
#else
#ifdef PRESSURE
typedef struct {
    Word perProcessTime, perJobTime;
    DWORD flags;
    Word minimumWorkingSet, maximumWorkingSet;
    DWORD activeProcesses;
    Word affinity;
    DWORD priority, scheduling;
    Word ioCounters[6], processMemory, jobMemory, peakProcessMemory, peakJobMemory;
} JobLimits;

IMPORT Handle CreateJobObjectA(void *, const char *);
IMPORT int SetInformationJobObject(Handle, int, const void *, DWORD);
IMPORT int AssignProcessToJobObject(Handle, Handle);
IMPORT Handle GetCurrentProcess(void);
#endif
static DWORD ran;

static int handler(void) {
    ++ran;
    return 0;
}

int entry(void) {
    int *error = _errno();
    DWORD stats[9] = {0};
    *error = 37;
    SetLastError(91);
    Handler result = _onexit(0);
    stats[0] = result == 0;
    stats[1] = GetLastError();
    stats[2] = *error;
    SetLastError(91);
    *error = 37;
#ifdef PRESSURE
    JobLimits limits = {0};
    limits.flags = 0x100; /* JOB_OBJECT_LIMIT_PROCESS_MEMORY */
    limits.processMemory = 32 * 1024 * 1024;
    Handle job = CreateJobObjectA(0, 0);
    if (!job || !SetInformationJobObject(job, 9, &limits, sizeof(limits)) ||
        !AssignProcessToJobObject(job, GetCurrentProcess())) {
        return 77;
    }
    SetLastError(91);
    *error = 37;
    const DWORD limit = 4000000;
#else
    const DWORD limit = 1;
#endif
    for (DWORD i = 0; i < limit; ++i) {
        result = _onexit(handler);
        if (result != handler) {
            stats[3] = result == 0 ? 1 : 2;
            break;
        }
        ++stats[4];
    }
    stats[5] = GetLastError();
    stats[6] = *error;
    _cexit();
    stats[7] = ran;
    stats[8] = *error;
    record(stats, sizeof(stats));
    return 42;
}
#endif
