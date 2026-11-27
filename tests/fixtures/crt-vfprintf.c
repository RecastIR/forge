#include <stdarg.h>

__declspec(dllimport) int vfprintf(void *stream, const char *format, va_list arguments);

__declspec(noinline) int emit(void *stream, const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    int result = vfprintf(stream, format, arguments);
    va_end(arguments);
    return result;
}
