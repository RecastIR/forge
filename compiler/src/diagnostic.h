#pragma once

#include "llvm/ADT/StringRef.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>

namespace forge {
    enum class FailureCode {
#define FORGE_FAILURE(name, wire, stage, category, legacy) name,
#include "diagnostics.def"
#undef FORGE_FAILURE
    };

    struct FailureKind {
        llvm::StringRef code, stage, category, legacy;
    };

    const FailureKind &failureKind(FailureCode code);

    // Errors can outlive the file, MC decoder and IR that supplied their context.
    struct CallLocation {
        uint32_t caller, instruction;
    };

    struct ImportOwnershipFailure {
        uint32_t descriptorRva;
        std::string reason;
    };

    struct FailureContext {
        std::filesystem::path input, output;
        std::optional<uint32_t> entryRva, endRva, instructionRva, blockRva, functionRva;
        // Source call evidence when the primary instruction belongs to an inferred callee.
        std::optional<CallLocation> sourceCall;
        std::optional<int64_t> branchTarget;
        std::optional<uint32_t> importSlot;
        std::optional<ImportOwnershipFailure> importOwnership;
        std::string importDll, importSymbol;
        std::optional<uint64_t> fileOffset;
        std::string opcode, bytes, architecture;
    };

    struct InspectionError : std::runtime_error {
        explicit InspectionError(const std::string &message,
                                 FailureCode kind = FailureCode::InvalidPe,
                                 std::string architecture = {});

        FailureCode kind;
        FailureContext context;
    };
} // namespace forge
