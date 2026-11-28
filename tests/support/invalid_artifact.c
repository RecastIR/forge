#include <forge/process.h>

#include <stdlib.h>
#include <string.h>

static void returnNormally(forge_rt_execution *execution) {
    execution->result = (forge_rt_process_result){.kind = FORGE_RT_RETURNED, .value = 42};
}

const forge_rt_artifact *forge_lifted_artifact(void) {
    static const forge_rt_artifact wrongEntry = {.version = FORGE_RT_ARTIFACT_VERSION,
                                                 .size = 3,
                                                 .entryRva = 1,
                                                 .peEntryRva = 2,
                                                 .entry = returnNormally};
    static const forge_rt_artifact zeroEntry = {
        .version = FORGE_RT_ARTIFACT_VERSION, .size = 3, .entry = returnNormally};
    // Both RVAs are valid, but registration must reject the missing native thunk.
    static const forge_rt_artifact invalidMapping = {
        .version = FORGE_RT_ARTIFACT_VERSION, .size = 3, .entryRva = 1, .peEntryRva = 1};
    const char *mode = getenv("FORGE_TEST_ARTIFACT");

    if (mode && strcmp(mode, "mismatch") == 0) {
        return &wrongEntry;
    }

    if (mode && strcmp(mode, "zero") == 0) {
        return &zeroEntry;
    }

    return &invalidMapping;
}
