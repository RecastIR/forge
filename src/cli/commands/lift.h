#pragma once

#include "lift/lift.h"

#include "llvm/Support/raw_ostream.h"

#include <filesystem>

namespace CLI {
    class App;
}

namespace forge::cli {
    struct LiftOptions {
        std::filesystem::path input, output;
        LiftRequest request{0, EntryMode::RegisterState};
        bool jsonDiagnostics = false;
    };

    void registerLift(CLI::App &app, LiftOptions &options, int &status);
    int executeLift(const LiftOptions &options, llvm::raw_ostream &err);
} // namespace forge::cli
