#include "forge.h"

#include "input.h"
#include "llvm/ADT/STLExtras.h"

#include <algorithm>
#include <map>
#include <variant>

namespace forge {
    namespace {
        using llvm::StringRef;
        namespace lfs = llvm::sys::fs;

        std::string classify(StringRef name) {
            static constexpr StringRef systemDlls[] = {
                "advapi32.dll",   "combase.dll", "gdi32.dll", "kernel32.dll",
                "kernelbase.dll", "ntdll.dll",   "ole32.dll", "shell32.dll",
                "shlwapi.dll",    "user32.dll",  "ws2_32.dll"};
            static constexpr StringRef runtimeDlls[] = {"msvcp140.dll", "msvcp140_1.dll",
                                                        "msvcp140_2.dll", "vcruntime140.dll",
                                                        "vcruntime140_1.dll"};
            if (llvm::is_contained(systemDlls, name)) {
                return "windows_system";
            }
            if (llvm::is_contained(runtimeDlls, name)) {
                return "third_party_runtime";
            }
            if (name.starts_with("api-ms-") || name.starts_with("ext-ms-") ||
                name.starts_with("api-win-") || name.starts_with("ext-win-")) {
                return "api_set";
            }
            return "unknown";
        }

        struct Directory {
            std::map<std::string, std::vector<fs::path>> byName;
            std::error_code error;

            explicit Directory(const fs::path &dir) {
                fs::directory_iterator it(dir, error);
                while (!error && it != fs::directory_iterator()) {
                    const auto path = it->path();
                    byName[StringRef(path.filename().native()).lower()].push_back(path);
                    it.increment(error);
                }
            }
        };

        void issue(Dependency &edge, std::string status, std::string code, std::string message) {
            edge.status = std::move(status);
            edge.code = std::move(code);
            edge.message = std::move(message);
        }

        void locate(Dependency &edge, const Import &import, const fs::path &parent,
                    const std::vector<fs::path> &searchPaths,
                    std::map<fs::path, Directory> &cache) {
            edge.kind = classify(import.normalizedName);
            if (edge.kind == "windows_system") {
                edge.status = "external_api";
                return;
            }
            if (edge.kind == "api_set") {
                issue(edge, "unresolved_contract", "API_SET_MAPPING_UNAVAILABLE",
                      "no API-set mapping configured");
                return;
            }
            std::vector<fs::path> dirs{parent};
            dirs.insert(dirs.end(), searchPaths.begin(), searchPaths.end());
            for (const auto &dir : dirs) {
                if (llvm::is_contained(edge.searched, dir)) {
                    continue;
                }
                edge.searched.push_back(dir);
                const Directory &listing = cache.try_emplace(dir, dir).first->second;
                if (listing.error) {
                    issue(edge, "inaccessible", "DLL_SEARCH_ERROR",
                          dir.string() + ": " + listing.error.message());
                    return;
                }
                auto it = listing.byName.find(import.normalizedName);
                if (it == listing.byName.end()) {
                    continue;
                }
                for (const auto &p : it->second) {
                    std::error_code ec;
                    if (!fs::is_directory(p, ec)) {
                        edge.candidates.push_back(p);
                    }
                }
                if (edge.candidates.empty()) {
                    continue;
                }
                edge.searchDirectory = dir;
                if (edge.candidates.size() > 1) {
                    std::sort(edge.candidates.begin(), edge.candidates.end());
                    issue(edge, "ambiguous", "DLL_AMBIGUOUS",
                          "multiple matching filenames in " + dir.string());
                } else {
                    edge.path = edge.candidates.front();
                    edge.candidates.clear();
                }
                return;
            }
            issue(edge, "missing", "DLL_NOT_FOUND",
                  "no matching DLL in the configured search directories");
        }

        using DllCache = std::map<lfs::UniqueID, std::variant<size_t, InspectionError>>;

        size_t loadModule(const fs::path &path, bool isRoot, DllCache &cache,
                          std::vector<Module> &modules) {
            InputFile input(path);
            auto id = input.id();
            if (auto it = cache.find(id); it != cache.end()) {
                if (auto *error = std::get_if<InspectionError>(&it->second)) {
                    throw *error;
                }
                return std::get<size_t>(it->second);
            }
            auto file = input.read();
            Module module;
            try {
                module = inspectPE(file->getMemBufferRef());
            } catch (const InspectionError &e) {
                cache.emplace(id, e);
                throw;
            }
            size_t index = modules.size();
            if (module.dll) {
                cache.emplace(id, index);
            } else {
                // A valid EXE root cannot satisfy a later DLL import through an alias.
                InspectionError error("expected a DLL image", "NOT_DLL");
                cache.emplace(id, error);
                if (!isRoot) {
                    throw error;
                }
            }
            module.path = path;
            modules.push_back(std::move(module));
            return index;
        }

        // Compute requiredness after discovery. A direct path can be discovered after
        // a delay-only path to the very same module.
        void markRequired(Report &report) {
            std::vector<std::vector<size_t>> outgoing(report.locations.size());
            for (size_t i = 0; i < report.dependencies.size(); ++i) {
                outgoing[report.dependencies[i].importerLocation].push_back(i);
            }
            std::vector<bool> reached(report.locations.size());
            std::vector<size_t> pending{0};
            reached[0] = true;
            while (!pending.empty()) {
                size_t source = pending.back();
                pending.pop_back();
                for (size_t i : outgoing[source]) {
                    auto &edge = report.dependencies[i];
                    if (report.modules[report.locations[source].module]
                            .imports[edge.importIndex]
                            .delayed) {
                        continue;
                    }
                    edge.required = true;
                    if (edge.targetLocation && !reached[*edge.targetLocation]) {
                        reached[*edge.targetLocation] = true;
                        pending.push_back(*edge.targetLocation);
                    }
                    if (edge.status != "resolved" && edge.status != "external_api") {
                        report.strictFailure = true;
                    }
                }
            }
        }
    } // namespace

    Report inspect(const fs::path &root, const std::vector<fs::path> &searchPaths) {
        Report report;
        DllCache files;
        std::map<std::pair<size_t, fs::path>, size_t> visited;
        std::map<fs::path, Directory> directories;
        auto visit = [&](const fs::path &path, bool isRoot) {
            std::error_code ec;
            auto canonical = fs::canonical(path, ec);
            if (ec) {
                throw InspectionError(ec.message(), "READ_ERROR");
            }
            size_t module = loadModule(canonical, isRoot, files, report.modules);
            auto [it, added] =
                visited.try_emplace({module, canonical.parent_path()}, report.locations.size());
            if (added) {
                report.locations.push_back({module, std::move(canonical)});
            }
            return it->second;
        };
        visit(root, true);
        for (size_t i = 0; i < report.locations.size(); ++i) {
            size_t module = report.locations[i].module;
            auto parent = report.locations[i].path.parent_path();
            for (size_t j = 0; j < report.modules[module].imports.size(); ++j) {
                Dependency edge{};
                edge.importerLocation = i;
                edge.importIndex = j;
                locate(edge, report.modules[module].imports[j], parent, searchPaths, directories);
                if (!edge.path.empty()) {
                    try {
                        edge.targetLocation = visit(edge.path, false);
                        edge.status = "resolved";
                        if (edge.kind == "unknown") {
                            edge.kind = "application";
                        }
                    } catch (const InspectionError &e) {
                        edge.architecture = e.architecture;
                        if (e.code == "READ_ERROR") {
                            issue(edge, "inaccessible", "DLL_READ_ERROR", e.what());
                        } else {
                            issue(edge, "incompatible",
                                  e.code == "UNSUPPORTED_ARCHITECTURE" ? "DLL_ARCH_MISMATCH"
                                                                       : "DLL_INVALID_IMAGE",
                                  e.what());
                        }
                    }
                }
                report.dependencies.push_back(std::move(edge));
            }
        }
        markRequired(report);
        return report;
    }
} // namespace forge
