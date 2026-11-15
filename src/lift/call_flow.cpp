#include "lift/call_flow.h"

#include <set>

namespace forge::x86 {
    bool Definitions::intersect(const Definitions &other) {
        const auto before = *this;
        flags &= other.flags;

        for (size_t i = 0; i < registers.size(); ++i) {
            registers[i] &= other.registers[i];
        }

        return *this != before;
    }

    Definitions DefinitionEffect::apply(Definitions incoming) const {
        incoming.flags = flags.apply(incoming.flags);

        for (size_t i = 0; i < writes.size(); ++i) {
            incoming.registers[i] |= writes[i];
        }

        return incoming;
    }

    void DefinitionEffect::append(const DefinitionEffect &next) {
        flags.generated = next.flags.apply(flags.generated);
        flags.carried = next.flags.apply(flags.carried);

        for (size_t i = 0; i < writes.size(); ++i) {
            writes[i] |= next.writes[i];
        }
    }

    bool DefinitionEffect::intersect(const DefinitionEffect &other) {
        const auto before = *this;
        flags.generated &= other.flags.generated;
        flags.carried &= other.flags.carried;

        for (size_t i = 0; i < writes.size(); ++i) {
            writes[i] &= other.writes[i];
        }

        return *this != before;
    }

    bool DefinitionEffect::operator==(const DefinitionEffect &other) const {
        return writes == other.writes && flags.generated == other.flags.generated &&
               flags.carried == other.flags.carried;
    }

    namespace {
        DefinitionEffect top() {
            DefinitionEffect result;
            result.writes.fill(UINT64_MAX);
            result.flags.generated.set();
            return result;
        }

        DefinitionEffect
        transfer(const BlockEffects &block, const FunctionFlows &flows,
                 llvm::function_ref<void(uint32_t, const DefinitionEffect &)> visit) {
            auto result = block.incoming;

            for (const auto &call : block.calls) {
                result.append(call.prefix);
                visit(call.target, result);
                result.append(flows.at(call.target).returns);
            }

            result.append(block.tail);
            return result;
        }

        // Meet over finite paths to RET. Starting at the greatest effect makes a
        // recursive cycle wait for its base cases instead of inventing an exit.
        DefinitionEffect returnEffect(const ControlFlowGraph &graph, FunctionFlow &function,
                                      const FunctionFlows &flows) {
            std::set<uint32_t> pending;

            for (auto &[address, block] : function.blocks) {
                block.incoming = top();
                pending.insert(address);
            }

            function.blocks.at(graph.begin()->first).incoming = {};
            auto returns = top();

            while (!pending.empty()) {
                const auto address = pending.extract(pending.begin()).value();
                const auto out = transfer(function.blocks.at(address), flows,
                                          [](uint32_t, const DefinitionEffect &) {});
                const auto &block = graph.at(address);

                if (block.exit == Flow::Return) {
                    returns.intersect(out);
                }

                for (auto successor : block.successors) {
                    if (function.blocks.at(successor).incoming.intersect(out)) {
                        pending.insert(successor);
                    }
                }
            }

            // Successful ABI checks preserve the caller's original definitions
            // of RSP and nonvolatiles even if a callee uses them as temporaries.
            std::fill(returns.writes.begin() + rspIndex, returns.writes.end(), 0);
            return returns;
        }
    } // namespace

    void proveCallFlow(const FunctionGraphs &graphs, FunctionFlows &flows, uint32_t root,
                       const Definitions &initial) {
        std::map<uint32_t, std::set<uint32_t>> callers;
        std::set<uint32_t> pending;

        for (auto &[address, function] : flows) {
            function.returns = top();
            pending.insert(address);

            for (const auto &[leader, block] : function.blocks) {
                for (const auto &call : block.calls) {
                    callers[call.target].insert(address);
                    flows.at(call.target).called = true;
                }
            }
        }

        while (!pending.empty()) {
            const auto address = pending.extract(pending.begin()).value();
            auto &function = flows.at(address);
            const auto returns = returnEffect(graphs.at(address), function, flows);

            if (function.returns != returns) {
                function.returns = returns;
                const auto &parents = callers[address];
                pending.insert(parents.begin(), parents.end());
            }
        }

        // Check each body using the intersection of the actual states from which
        // it can be entered. Return effects remain specific to each caller's input.
        for (auto &[address, function] : flows) {
            function.entry.registers.fill(UINT64_MAX);
            function.entry.flags.set();
            pending.insert(address);
        }

        flows.at(root).entry = initial;

        while (!pending.empty()) {
            const auto address = pending.extract(pending.begin()).value();
            const auto &function = flows.at(address);
            const auto entry = function.entry;
            auto visit = [&](uint32_t target, const DefinitionEffect &prefix) {
                const auto atCall = prefix.apply(entry);
                auto &incoming = flows.at(target).entry;

                if (incoming.intersect(atCall)) {
                    pending.insert(target);
                }
            };

            for (const auto &[leader, block] : function.blocks) {
                transfer(block, flows, visit);
            }
        }
    }
} // namespace forge::x86
