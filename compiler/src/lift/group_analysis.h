#pragma once

#include "lift/call_flow.h"
#include "lift/image_memory.h"
#include "lift/lift.h"

#include "llvm/ADT/DenseSet.h"

namespace forge::x86 {
    class RecoveredFunctionGroup;

    struct FunctionPlan {
        RegisterSet modified;
        llvm::DenseSet<uint32_t> stackAccesses;
    };

    // Proofs reference validated call sites in the recovered group. Access routes and
    // selected image bytes are derived for this guest base and entry contract.
    struct GroupAnalysis {
        FunctionFlows flows;
        std::map<uint32_t, FunctionPlan> functions;
        bool stack = false, origins = false, setsDirection = false;
        ImagePlan image;
    };

    Defined entryRegisterDefinitions(EntryMode mode);

    // The group must outlive its proofs. Use a guest base validated for this image.
    GroupAnalysis analyzeGroup(const RecoveredFunctionGroup &group, uint64_t guestBase,
                               EntryMode mode, bool checkedMemory = false,
                               LiftOutput output = LiftOutput::Function);
    GroupAnalysis analyzeGroup(const RecoveredFunctionGroup &&, uint64_t, EntryMode,
                               bool checkedMemory = false,
                               LiftOutput output = LiftOutput::Function) = delete;
} // namespace forge::x86
