#include "analysis/analysis.h"

#include "llvm/Support/Endian.h"

#include <utility>

namespace forge {
    namespace {
        using llvm::support::endian::read32le;

        void inspectScope(const AnalyzedImage &analysis, const FunctionRange &owner,
                          const StableMetadata &stable, CSpecificHandler &handler) {
            const auto table = analysis.image().mapRva(handler.tableRva);
            constexpr uint32_t countSize = 4, scopeSize = 16;
            if (!table || table->bytes.size() < countSize) {
                handler.failure = FailureCode::InvalidPe;
                handler.limitation = "truncated C-specific scope count";
                return;
            }

            if (!stable.contains(handler.tableRva, countSize)) {
                handler.limitation = "mutable C-specific scope count";
                return;
            }

            handler.count = read32le(table->bytes.data());
            const auto extent = countSize + uint64_t(*handler.count) * scopeSize;
            if (extent > table->bytes.size()) {
                handler.failure = FailureCode::InvalidPe;
                handler.limitation = "truncated C-specific scope array";
                return;
            }

            if (*handler.count != 1) {
                handler.limitation = "expected one C-specific exception scope";
                return;
            }

            if (!stable.contains(owner.record.unwind,
                                 handler.tableRva - owner.record.unwind + countSize + scopeSize)) {
                handler.limitation = "mutable or split C-specific unwind and scope table";
                return;
            }

            const auto *row = table->bytes.data() + countSize;
            const CExceptionScope scope{read32le(row), read32le(row + 4), read32le(row + 8),
                                        read32le(row + 12)};
            if (scope.beginRva < owner.record.begin || scope.beginRva >= scope.endRva ||
                scope.endRva > owner.record.end) {
                handler.limitation = "C-specific protected range outside its owning function";
                return;
            }

            if (!scope.jumpRva || scope.filterRva == 1) {
                handler.limitation = "C-specific termination or constant filter scope";
                return;
            }

            if (scope.jumpRva < owner.record.begin || scope.jumpRva >= owner.record.end) {
                handler.limitation = "C-specific continuation outside its owning function";
                return;
            }

            const auto filter =
                llvm::lower_bound(analysis.functions(), scope.filterRva,
                                  [](const auto &f, uint32_t rva) { return f.record.begin < rva; });
            if (filter == analysis.functions().end() || filter->record.begin != scope.filterRva ||
                !filter->eligible()) {
                handler.limitation = "C-specific filter has no eligible function record";
                return;
            }

            if (!stable.containsUnwindRecord(*filter)) {
                handler.limitation = "mutable C-specific filter unwind metadata";
                return;
            }

            handler.scope = scope;
            handler.limitation = "guest exception dispatch and unwind are unsupported";
        }
    } // namespace

    std::optional<CSpecificHandler>
    AnalyzedImage::cSpecificHandler(const FunctionRange &function) const {
        if (!function.handlerRva || !function.exceptionDataRva || !function.eligible() ||
            source->advertisesDynamicRelocations()) {
            return {};
        }

        const auto thunk = source->mapRva(*function.handlerRva, amd64ImportThunkSize);
        if (!thunk || thunk->section.permissions[2] != 'x') {
            return {};
        }

        const auto slot = amd64ImportThunkSlot(*function.handlerRva, thunk->bytes);
        if (!slot || !std::in_range<uint32_t>(*slot)) {
            return {};
        }

        const auto imported = source->importBindings().at(static_cast<uint32_t>(*slot));
        if (!imported || imported->descriptor.delayed || imported->descriptor.bound ||
            imported->symbol.ordinal || imported->symbol.name != "__C_specific_handler" ||
            (imported->descriptor.normalizedName != "msvcrt.dll" &&
             imported->descriptor.normalizedName != "kernel32.dll")) {
            return {};
        }

        const RelocationIndex relocations(module().relocations);
        const auto writes = source->loaderWrittenRanges();
        const StableMetadata stable{*source, relocations, writes};
        if (!stable.containsUnwindRecord(function) ||
            !stable.contains(*function.handlerRva, amd64ImportThunkSize) ||
            imported->unstableIdentityRva(stable.relocations, stable.writes)) {
            return {};
        }

        CSpecificHandler handler{imported->descriptor.name,
                                 static_cast<uint32_t>(*slot),
                                 *function.exceptionDataRva,
                                 {},
                                 {},
                                 FailureCode::ExecutableStartup,
                                 {}};
        inspectScope(*this, function, stable, handler);
        return handler;
    }
} // namespace forge
