#include "lift/call_flow.h"
#include "lift/recovery.h"

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
            incoming.registers[i] = writes[i] | (carried[i] & incoming.registers[i]);
        }

        return incoming;
    }

    void DefinitionEffect::append(const DefinitionEffect &next) {
        flags.generated = next.flags.apply(flags.generated);
        flags.carried = next.flags.apply(flags.carried);

        for (size_t i = 0; i < writes.size(); ++i) {
            writes[i] = next.writes[i] | (writes[i] & next.carried[i]);
            carried[i] = next.writes[i] | (carried[i] & next.carried[i]);
        }
    }

    bool DefinitionEffect::intersect(const DefinitionEffect &other) {
        const auto before = *this;
        flags.generated &= other.flags.generated;
        flags.carried &= other.flags.carried;

        for (size_t i = 0; i < writes.size(); ++i) {
            writes[i] &= other.writes[i];
            carried[i] &= other.carried[i];
        }

        return *this != before;
    }

    bool DefinitionEffect::operator==(const DefinitionEffect &other) const {
        return writes == other.writes && carried == other.carried &&
               flags.generated == other.flags.generated && flags.carried == other.flags.carried;
    }

    DefinitionEffect callEffect(const ResolvedCallSite &site, const FunctionFlows &flows) {
        const auto *external = site.external();
        if (!external) {
            return flows.at(site.guest().rva).returns;
        }

        DefinitionEffect result;
        std::fill_n(result.carried.begin(), callerSlots, 0);
        result.flags = {};
        if (external->binding.result != win64::Value::Void) {
            // Both full RAX writes and zero-extending EAX writes define all 64 bits.
            result.writes[0] = result.carried[0] = UINT64_MAX;
        }

        return result;
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
                if (!call.site->external()) {
                    visit(call.site->guest().rva, result);
                }

                result.append(callEffect(*call.site, flows));
            }

            result.append(block.tail);
            return result;
        }

        // Meet over finite paths to RET. Starting at the greatest effect makes a
        // recursive cycle wait for its base cases instead of inventing an exit.
        DefinitionEffect returnEffect(const RecoveredFunction &recovered, FunctionFlow &function,
                                      const FunctionFlows &flows) {
            std::set<uint32_t> pending;

            for (auto &[address, block] : function.blocks) {
                block.incoming = top();
                pending.insert(address);
            }

            function.blocks.at(recovered.entry).incoming = {};
            auto returns = top();

            while (!pending.empty()) {
                const auto address = pending.extract(pending.begin()).value();
                const auto out = transfer(function.blocks.at(address), flows,
                                          [](uint32_t, const DefinitionEffect &) {});
                const auto &block = recovered.graph.at(address);

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

    void proveCallFlow(const RecoveredFunctionGroup &group, FunctionFlows &flows,
                       const Definitions &initial) {
        std::set<uint32_t> pending;

        for (auto &[address, function] : flows) {
            function.returns = top();
            pending.insert(address);
        }

        while (!pending.empty()) {
            const auto address = pending.extract(pending.begin()).value();
            auto &function = flows.at(address);
            const auto &recovered = group.function(address);
            const auto returns = returnEffect(recovered, function, flows);

            if (function.returns != returns) {
                function.returns = returns;

                for (const auto *site : recovered.incoming) {
                    pending.insert(site->caller);
                }
            }
        }

        // Check each body using the intersection of the actual states from which
        // it can be entered. Return effects remain specific to each caller's input.
        for (auto &[address, function] : flows) {
            function.entry.registers.fill(UINT64_MAX);
            function.entry.flags.set();
            pending.insert(address);
        }

        flows.at(group.root()).entry = initial;

        // Native CRT calls supply no register arguments or arithmetic flags. Meet this
        // entry with ordinary callers' definitions when one body has both kinds of edge.
        Definitions initializer{};
        initializer.registers[rspIndex] = UINT64_MAX;
        for (const auto &[address, function] : group.functions()) {
            if (function.initializerSource) {
                flows.at(address).entry.intersect(initializer);
            }
        }

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
