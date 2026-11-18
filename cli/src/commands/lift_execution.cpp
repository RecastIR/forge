#include "analysis_input.h"
#include "commands/lift.h"
#include "output/publication.h"
#include "report.h"

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"

namespace forge::cli {
    namespace {
        void reportLiftFailure(const LiftOptions &options, const ExecutableReadiness &readiness,
                               const InspectionError &error, llvm::raw_ostream &err) {
            if (options.executable) {
                printExecutableDiagnostic(readiness, options.input, options.output, &error,
                                          options.jsonDiagnostics, err);
            } else if (options.jsonDiagnostics) {
                printLiftDiagnostic(error, options.input, options.request, err);
            } else {
                printFailure(error, options.input, err);
            }
        }
    } // namespace

    int executeLift(const LiftOptions &options, llvm::raw_ostream &err) {
        FailureCode stage = FailureCode::InputInternal;
        ExecutableReadiness readiness;

        try {
            const auto analysis = analyzeInput(options.input, DebugInfo::Omit, stage);
            stage = FailureCode::PublicationInternal;
            (void)checkedOutputDestination(analysis.image(), options.output);

            stage = FailureCode::LiftingInternal;
            llvm::LLVMContext context;

            if (options.executable) {
                const auto module =
                    generateExecutableIR(analysis, std::nullopt, context, readiness);
                stage = FailureCode::PublicationInternal;
                publishExecutable(*module, analysis.image(), options.output, options.toolchain,
                                  /*optimize=*/true);
                printExecutableDiagnostic(readiness, options.input, options.output, nullptr,
                                          options.jsonDiagnostics, err);
            } else {
                const auto module = generateIR(analysis, options.request, context);
                stage = FailureCode::PublicationInternal;
                publishIR(*module, analysis.image(), options.output);
            }

            return 0;
        } catch (const InspectionError &error) {
            if (error.kind == FailureCode::OutputAlias && !options.executable) {
                throw std::invalid_argument(error.what());
            }

            reportLiftFailure(options, readiness, error, err);
            return 1;
        } catch (const std::exception &error) {
            if (!options.jsonDiagnostics && !options.executable) {
                throw;
            }

            InspectionError failure(error.what(), stage);

            if (stage == FailureCode::PublicationInternal) {
                failure.context.output = options.output;
            }

            reportLiftFailure(options, readiness, failure, err);
            return 1;
        }
    }
} // namespace forge::cli
