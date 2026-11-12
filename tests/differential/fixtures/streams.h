#pragma once

#include <fcntl.h>
#include <io.h>
#include <stdio.h>

// Preserve the manifest's UTF-8 bytes, including LF, when the CRT writes to pipes.
static inline int open_binary_streams(void) {
    return _setmode(_fileno(stdout), _O_BINARY) != -1 && _setmode(_fileno(stderr), _O_BINARY) != -1;
}
