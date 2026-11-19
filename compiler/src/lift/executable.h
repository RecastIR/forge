#pragma once

#include "lift/lift.h"
#include "lift/recovery.h"

namespace forge::x86 {
    std::optional<uint32_t> crtDataExport(const Import &descriptor, const Symbol &symbol);

    void recordExecutableRequirements(const AnalyzedImage &analysis,
                                      ExecutableReadiness &readiness);

    void recordExecutableRecovery(ExecutableReadiness &readiness,
                                  const RecoveredFunctionGroup &group,
                                  const InspectionError *failure = nullptr);

    void validateExecutableStartup(const ValidatedEntry &entry, const RecoveredFunctionGroup &group,
                                   uint64_t guestBase, ExecutableReadiness &readiness);
} // namespace forge::x86
