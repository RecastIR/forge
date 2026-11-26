#pragma once

#include "lift/integer.h"

#include <map>
#include <vector>

namespace forge::x86 {
    struct ResolvedCallSite;
    class RecoveredFunctionGroup;

    inline constexpr unsigned registerCount = 16;
    inline constexpr unsigned callerSlots = 7;
    inline constexpr unsigned rspIndex = callerSlots;
    using Defined = std::array<uint64_t, registerCount>;
    using RegisterSet = std::bitset<registerCount>;

    struct Definitions {
        Defined registers{};
        FlagSet flags;
        bool intersect(const Definitions &other);
        bool operator==(const Definitions &) const = default;
    };

    // The two flag masks give the output with no incoming flags and with all
    // incoming flags. This also represents a join of a definition and a pass-through.
    struct DefinitionEffect {
        Defined writes{};
        Defined carried = [] {
            Defined bits;
            bits.fill(UINT64_MAX);
            return bits;
        }();
        FlagEffect flags{{}, FlagSet().set()};
        Definitions apply(Definitions incoming) const;
        void append(const DefinitionEffect &next);
        bool intersect(const DefinitionEffect &other);
        bool operator==(const DefinitionEffect &other) const;
    };

    struct CallSiteEffect {
        // The recovered group owns the validated site for the lifetime of the proof.
        const ResolvedCallSite *site;
        DefinitionEffect prefix;
    };

    struct BlockEffects {
        // Effects between calls compose in guest instruction order.
        std::vector<CallSiteEffect> calls;
        DefinitionEffect tail;
        DefinitionEffect incoming;
    };

    struct FunctionFlow {
        std::map<uint32_t, BlockEffects> blocks;
        DefinitionEffect returns;
        Definitions entry;
        bool mayReturn = false;
    };

    using FunctionFlows = std::map<uint32_t, FunctionFlow>;

    DefinitionEffect callEffect(const ResolvedCallSite &site, const FunctionFlows &flows);

    void proveCallFlow(const RecoveredFunctionGroup &group, FunctionFlows &flows,
                       const Definitions &initial);
} // namespace forge::x86
