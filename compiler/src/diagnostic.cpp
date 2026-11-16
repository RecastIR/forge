#include "diagnostic.h"

#include <cstddef>
#include <utility>

namespace forge {
    const FailureKind &failureKind(FailureCode code) {
        static constexpr FailureKind kinds[] = {
#define FORGE_FAILURE(name, wire, stage, category, legacy) {wire, stage, category, legacy},
#include "diagnostics.def"
#undef FORGE_FAILURE
        };
        return kinds[static_cast<size_t>(code)];
    }

    InspectionError::InspectionError(const std::string &message, FailureCode kind,
                                     std::string architecture)
        : runtime_error(message), kind(kind) {
        context.architecture = std::move(architecture);
    }
} // namespace forge
