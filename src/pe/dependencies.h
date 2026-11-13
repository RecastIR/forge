#pragma once

#include "image.h"

namespace forge {
    struct ModuleLocation {
        size_t module;
        fs::path path; // First canonical alias encountered in this directory.
    };

    struct Dependency {
        size_t importerLocation, importIndex;
        bool required = false;
        std::string kind, status;
        std::optional<size_t> targetLocation;
        fs::path path, searchDirectory;
        std::vector<fs::path> searched, candidates;
        std::string code, message, architecture;
    };

    struct Report {
        std::vector<Module> modules; // Root first, then deterministic discovery order.
        std::vector<ModuleLocation> locations;
        std::vector<Dependency> dependencies;
        bool strictFailure = false;
    };

    Report inspect(const fs::path &root, const std::vector<fs::path> &searchPaths);
} // namespace forge
