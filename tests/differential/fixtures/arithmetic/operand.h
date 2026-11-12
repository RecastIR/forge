#pragma once

#include <inttypes.h>

// Both console drivers accept bounded decimal pairs. Their sum always fits int64_t.
static inline int parse_operand(const char* text, int64_t* value) {
    const char* digits = *text == '-' ? text + 1 : text;
    if (*digits < '0' || *digits > '9')
        return 0;
    char* end;
    const intmax_t parsed = strtoimax(text, &end, 10);
    if (*end || parsed < -INT64_C(9999999999) || parsed > INT64_C(9999999999))
        return 0;
    *value = (int64_t)parsed;
    return 1;
}
