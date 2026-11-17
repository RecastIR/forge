#include <forge/runtime.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static void require(bool passed, const char *message) {
    if (!passed) {
        fputs(message, stderr);
        exit(EXIT_FAILURE);
    }
}

#define REQUIRE(expr) require((expr), "Runtime ABI check failed: " #expr "\n")

_Static_assert(sizeof(forge_rt_status) == 4, "ABI status width");
_Static_assert(sizeof(forge_rt_thread_token) == 8, "ABI thread token width");
_Static_assert(sizeof(forge_rt_invocation_token) == 8, "ABI invocation token width");

static void checkArguments(forge_rt_instance *runtime) {
    forge_rt_instance *output = runtime;
    REQUIRE(forge_rt_create(FORGE_RT_ABI_VERSION + 1, &output) == FORGE_RT_ABI_MISMATCH);
    REQUIRE(output == runtime);
    REQUIRE(forge_rt_create(FORGE_RT_ABI_VERSION, NULL) == FORGE_RT_INVALID_ARGUMENT);
    REQUIRE(forge_rt_destroy(NULL) == FORGE_RT_INVALID_ARGUMENT);

    forge_rt_thread_token token = 42;
    REQUIRE(forge_rt_thread_create(NULL, &token) == FORGE_RT_INVALID_ARGUMENT);
    REQUIRE(token == 42);
    REQUIRE(forge_rt_thread_create(runtime, NULL) == FORGE_RT_INVALID_ARGUMENT);
    REQUIRE(forge_rt_thread_destroy(NULL, token) == FORGE_RT_INVALID_ARGUMENT);
    REQUIRE(forge_rt_thread_destroy(runtime, 0) == FORGE_RT_INVALID_THREAD);
    REQUIRE(forge_rt_set_last_error(NULL, token, 7) == FORGE_RT_INVALID_ARGUMENT);

    uint32_t value = 123;
    REQUIRE(forge_rt_get_last_error(NULL, token, &value) == FORGE_RT_INVALID_ARGUMENT);
    REQUIRE(forge_rt_get_last_error(runtime, 0, &value) == FORGE_RT_INVALID_THREAD);
    REQUIRE(value == 123);
    REQUIRE(forge_rt_thread_create(runtime, &token) == FORGE_RT_OK);
    REQUIRE(forge_rt_get_last_error(runtime, token, NULL) == FORGE_RT_INVALID_ARGUMENT);
    REQUIRE(forge_rt_thread_destroy(runtime, token) == FORGE_RT_OK);
}

static void checkIsolation(forge_rt_instance *first, forge_rt_instance *second) {
    forge_rt_thread_token a = 0, b = 0, c = 0;
    REQUIRE(forge_rt_thread_create(first, &a) == FORGE_RT_OK);
    REQUIRE(forge_rt_thread_create(first, &b) == FORGE_RT_OK);
    REQUIRE(forge_rt_thread_create(second, &c) == FORGE_RT_OK);
    uint32_t value = 17;
    REQUIRE(forge_rt_get_last_error(first, a, &value) == FORGE_RT_OK && value == 0);
    REQUIRE(forge_rt_set_last_error(first, a, UINT32_MAX) == FORGE_RT_OK);
    REQUIRE(forge_rt_set_last_error(first, b, 0x80000000U) == FORGE_RT_OK);
    REQUIRE(forge_rt_set_last_error(second, c, 3) == FORGE_RT_OK);
    REQUIRE(forge_rt_get_last_error(first, a, &value) == FORGE_RT_OK && value == UINT32_MAX);
    REQUIRE(forge_rt_get_last_error(first, b, &value) == FORGE_RT_OK && value == 0x80000000U);
    forge_rt_thread_token highBits = a ^ UINT64_C(0x8000000000000000);
    REQUIRE(forge_rt_get_last_error(first, highBits, &value) == FORGE_RT_INVALID_THREAD);
    REQUIRE(value == 0x80000000U);
    REQUIRE(forge_rt_thread_destroy(first, c) == FORGE_RT_INVALID_THREAD);
    REQUIRE(forge_rt_set_last_error(second, a, 4) == FORGE_RT_INVALID_THREAD);
    REQUIRE(forge_rt_get_last_error(first, c, &value) == FORGE_RT_INVALID_THREAD);
    REQUIRE(value == 0x80000000U);
    REQUIRE(forge_rt_get_last_error(second, c, &value) == FORGE_RT_OK && value == 3);

    REQUIRE(forge_rt_thread_destroy(first, a) == FORGE_RT_OK);
    REQUIRE(forge_rt_thread_destroy(first, a) == FORGE_RT_INVALID_THREAD);
    forge_rt_thread_token replacement = 0;
    REQUIRE(forge_rt_thread_create(first, &replacement) == FORGE_RT_OK);
    REQUIRE(forge_rt_set_last_error(first, a, 99) == FORGE_RT_INVALID_THREAD);
    REQUIRE(forge_rt_get_last_error(first, a, &value) == FORGE_RT_INVALID_THREAD && value == 3);
    REQUIRE(forge_rt_get_last_error(first, replacement, &value) == FORGE_RT_OK && value == 0);
}

static void checkMemory(forge_rt_instance *runtime) {
    const uint8_t byte = 19;
    const forge_rt_image_region row = {0x1000, 1, &byte, FORGE_RT_READ, NULL};
    const forge_rt_image image = {0x1000, 1, &row, 1};
    forge_rt_thread_token thread = 0;
    forge_rt_invocation_token invocation = 0, current = 17;
    REQUIRE(forge_rt_thread_create(runtime, &thread) == FORGE_RT_OK);
    REQUIRE(forge_rt_current_invocation(runtime, thread, &current) == FORGE_RT_INVALID_INVOCATION);
    REQUIRE(current == 17);
    REQUIRE(forge_rt_enter(runtime, thread, &image, NULL, &invocation) == FORGE_RT_OK);
    REQUIRE(invocation != 0);
    REQUIRE(forge_rt_current_invocation(runtime, thread, &current) == FORGE_RT_OK);
    REQUIRE(current == invocation);

    int32_t length = 17;
    forge_rt_memory_fault stringFault = {7, 8, 9};
    REQUIRE(forge_rt_lstrlen_a(runtime, thread, 0, &length, &stringFault) == FORGE_RT_OK);
    REQUIRE(length == 0 && stringFault.address == 7 && stringFault.access == 8 &&
            stringFault.reason == 9);

    REQUIRE(forge_rt_enter(runtime, thread, &image, NULL, &current) == FORGE_RT_BUSY);
    REQUIRE(current == invocation);

    uint8_t result = 9;
    forge_rt_memory_fault fault = {7, 8, 9};
    REQUIRE(forge_rt_read_guest(runtime, thread, current, row.start, 1, &result, 1, &fault) ==
            FORGE_RT_OK);
    REQUIRE(result == byte && fault.address == 7 && fault.access == 8 && fault.reason == 9);
    REQUIRE(forge_rt_write_guest(runtime, thread, current, row.start, 1, &result, 1, &fault) ==
            FORGE_RT_GUEST_FAULT);
    REQUIRE(fault.address == row.start && fault.access == FORGE_RT_WRITE &&
            fault.reason == FORGE_RT_FAULT_PERMISSION);
    REQUIRE(forge_rt_leave(runtime, thread, invocation) == FORGE_RT_OK);
    REQUIRE(forge_rt_detach_image(runtime, &image) == FORGE_RT_OK);
    REQUIRE(forge_rt_thread_destroy(runtime, thread) == FORGE_RT_OK);
}

int main(void) {
    forge_rt_instance *first = NULL, *second = NULL;
    REQUIRE(forge_rt_create(FORGE_RT_ABI_VERSION, &first) == FORGE_RT_OK);
    REQUIRE(forge_rt_destroy(first) == FORGE_RT_OK);
    REQUIRE(forge_rt_create(FORGE_RT_ABI_VERSION, &first) == FORGE_RT_OK);
    forge_rt_thread_token retired = 0;
    REQUIRE(forge_rt_thread_create(first, &retired) == FORGE_RT_OK);
    REQUIRE(forge_rt_destroy(first) == FORGE_RT_OK);
    REQUIRE(forge_rt_create(FORGE_RT_ABI_VERSION, &first) == FORGE_RT_OK);

    REQUIRE(forge_rt_create(FORGE_RT_ABI_VERSION, &second) == FORGE_RT_OK);
    checkArguments(first);
    checkIsolation(first, second);
    checkMemory(first);
    REQUIRE(forge_rt_set_last_error(first, retired, 42) == FORGE_RT_INVALID_THREAD);

    // The first runtime owns two remaining threads and the second owns one.
    REQUIRE(forge_rt_destroy(first) == FORGE_RT_OK);
    REQUIRE(forge_rt_destroy(second) == FORGE_RT_OK);
    return 0;
}
