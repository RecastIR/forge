#pragma once

#include "lift/cfg.h"
#include "lift/integer.h"

#include <set>

namespace forge::x86 {
    inline constexpr unsigned registerCount = 16;
    inline constexpr unsigned callerSlots = 7;
    inline constexpr unsigned rspIndex = callerSlots;
    using Defined = std::array<uint64_t, registerCount>;

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
        FlagEffect flags{{}, FlagSet().set()};
        Definitions apply(Definitions incoming) const;
        void append(const DefinitionEffect &next);
        bool intersect(const DefinitionEffect &other);
        bool operator==(const DefinitionEffect &other) const;
    };

    struct CallSiteEffect {
        uint32_t target, continuation;
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
        std::set<uint32_t> callers;
        std::vector<uint32_t> continuations;
    };

    using FunctionGraphs = std::map<uint32_t, ControlFlowGraph>;
    using FunctionFlows = std::map<uint32_t, FunctionFlow>;

    void proveCallFlow(const FunctionGraphs &graphs, FunctionFlows &flows, uint32_t root,
                       const Definitions &initial);
} // namespace forge::x86
