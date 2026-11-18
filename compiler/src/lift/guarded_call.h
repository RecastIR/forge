#pragma once

#include "lift/operands.h"
#include "pe/image.h"

namespace forge::x86 {
    std::optional<GuardedPointerCall>
    recognizeGuardedPointerCall(const std::map<uint32_t, Step> &decoded, const Step &call,
                                const InstructionOperands &operands);
    uint32_t guardedCallTarget(const Step &call, uint32_t slot, const ParsedImage &image,
                               const ImageInitialization &init);
} // namespace forge::x86
