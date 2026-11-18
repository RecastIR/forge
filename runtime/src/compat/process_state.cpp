#include "process_state.h"

#include "../core/instance.h"

#include <algorithm>
#include <bit>

namespace forge::runtime {
    forge_rt_status WindowsProcessState::initializeParameters(
        forge_rt_instance &instance, const forge_rt_artifact &artifact,
        const forge_rt_process_startup &startup, bool osCommandLine, CrtImports imports) {
        if (osCommandLine || imports.mainArgs || imports.hasData(FORGE_RT_CRT_ACMDLN)) {
            const auto result = parameters.buildCommandLine(artifact, startup);

            if (result != FORGE_RT_OK) {
                return result;
            }
        }

        if (osCommandLine) {
            static_assert(std::endian::native == std::endian::little && sizeof(char16_t) == 2);
            parameters.wide.assign(parameters.narrow.begin(), parameters.narrow.end());
        }

        if (imports.mainArgs || !imports.data.empty()) {
            const auto status = crt.emplace().initialize(imports, parameters.narrow, startup);

            if (status != FORGE_RT_OK) {
                return status;
            }
        }

        // Keep all unimplemented TEB fields in a reserved hole. The CRT data and
        // strings live beyond the TEB, not at unimplemented Windows structure offsets.
        constexpr uint64_t parameterOffset = 65536;
        constexpr uint64_t stringOffset = parameterOffset + sizeof(crtErrno);
        const auto narrowSize = parameters.narrow.size() + 1;
        const auto wideSize = (parameters.wide.size() + 1) * sizeof(char16_t);
        const auto wideOffset = (narrowSize + 1) & ~size_t{1};
        const auto stringEnd = stringOffset + (osCommandLine ? wideOffset + wideSize : 0);
        const auto crtOffset = (stringEnd + 7) & ~uint64_t{7};
        const auto size = crt ? crtOffset + crt->bytes.size() : stringEnd;
        std::array<Reservation, 2> occupied{
            {{artifact.base, artifact.size, nullptr, nullptr},
             {FORGE_RT_STACK_BASE, FORGE_RT_STACK_SIZE, nullptr, nullptr}}};
        std::ranges::sort(occupied, {}, &Reservation::base);
        const auto base = findGuestAllocation(occupied, size, parameterOffset);

        if (!base) {
            return FORGE_RT_MAPPING_CONFLICT;
        }

        // Only implemented NT_TIB fields occupy rows. A guest may write its own TIB.
        constexpr auto permissions = FORGE_RT_READ | FORGE_RT_WRITE;
        parameters.self = base;
        rows[0] = {base + 8, sizeof(parameters.stackBounds), parameters.stackBounds.data(),
                   permissions, &parameters.tibClaim};
        rows[1] = {base + 0x30, sizeof(parameters.self), &parameters.self, permissions,
                   &parameters.tibClaim};

        rows[errnoRow] = {base + parameterOffset, sizeof(crtErrno), &crtErrno, permissions,
                          &parameters.tibClaim};

        if (osCommandLine) {
            const auto stringBase = base + stringOffset;
            rows[narrowCommandRow] = {stringBase, narrowSize, parameters.narrow.c_str(),
                                      FORGE_RT_READ, nullptr};
            rows[wideCommandRow] = {stringBase + wideOffset, wideSize, parameters.wide.c_str(),
                                    FORGE_RT_READ, nullptr};
        }

        size_t rowCount = osCommandLine ? wideCommandRow + 1 : errnoRow + 1;

        if (crt) {
            const auto crtBase = base + crtOffset;
            crt->relocate(crtBase);
            rows[rowCount++] = {crtBase, crt->bytes.size(), crt->bytes.data(), permissions,
                                &crt->claim};
        }

        mapping = {base, size, rows.data(), rowCount};
        return forge_rt_register_image(&instance, &mapping);
    }
} // namespace forge::runtime
