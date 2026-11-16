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
    REQUIRE(forge_rt_set_last_error(first, retired, 42) == FORGE_RT_INVALID_THREAD);

    // The first runtime owns two remaining threads and the second owns one.
    REQUIRE(forge_rt_destroy(first) == FORGE_RT_OK);
    REQUIRE(forge_rt_destroy(second) == FORGE_RT_OK);
    return 0;
}
