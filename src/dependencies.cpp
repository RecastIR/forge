#include "forge.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"

#include <algorithm>
#include <map>
#include <variant>

namespace forge {
namespace {
using llvm::StringRef;
namespace lfs = llvm::sys::fs;

std::string classify(StringRef name) {
  static constexpr StringRef system[] = {
      "advapi32.dll", "combase.dll", "gdi32.dll",   "kernel32.dll", "kernelbase.dll", "ntdll.dll",
      "ole32.dll",    "shell32.dll", "shlwapi.dll", "user32.dll",   "ws2_32.dll"};
  static constexpr StringRef runtime[] = {"msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll",
                                          "vcruntime140.dll", "vcruntime140_1.dll"};
  if (llvm::is_contained(system, name))
    return "windows_system";
  if (llvm::is_contained(runtime, name))
    return "third_party_runtime";
  if (name.starts_with("api-ms-") || name.starts_with("ext-ms-") || name.starts_with("api-win-") ||
      name.starts_with("ext-win-"))
    return "api_set";
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
            const std::vector<fs::path> &searchPaths, std::map<fs::path, Directory> &cache) {
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
    if (llvm::is_contained(edge.searched, dir))
      continue;
    edge.searched.push_back(dir);
    const Directory &listing = cache.try_emplace(dir, dir).first->second;
    if (listing.error) {
      issue(edge, "inaccessible", "DLL_SEARCH_ERROR",
            dir.string() + ": " + listing.error.message());
      return;
    }
    auto it = listing.byName.find(import.normalizedName);
    if (it == listing.byName.end())
      continue;
    for (const auto &p : it->second) {
      std::error_code ec;
      if (!fs::is_directory(p, ec))
        edge.candidates.push_back(p);
    }
    if (edge.candidates.empty())
      continue;
    edge.searchDirectory = dir;
    if (edge.candidates.size() > 1) {
      std::sort(edge.candidates.begin(), edge.candidates.end());
      issue(edge, "ambiguous", "DLL_AMBIGUOUS", "multiple matching filenames in " + dir.string());
    } else {
      edge.path = edge.candidates.front();
      edge.candidates.clear();
    }
    return;
  }
  issue(edge, "missing", "DLL_NOT_FOUND", "no matching DLL in the configured search directories");
}

lfs::UniqueID identity(const fs::path &path) {
  lfs::file_status status;
  if (auto ec = lfs::status(path.native(), status))
    throw InspectionError(ec.message(), "READ_ERROR");
  if (!lfs::is_regular_file(status))
    throw InspectionError("expected a regular file", "READ_ERROR");
  return status.getUniqueID();
}

Module load(const fs::path &path) {
  auto file = llvm::MemoryBuffer::getFile(path.native(), false, false, true);
  if (!file)
    throw InspectionError(file.getError().message(), "READ_ERROR");
  Module module = inspectPE((*file)->getMemBufferRef());
  std::error_code ec;
  module.path = fs::canonical(path, ec);
  if (ec)
    throw InspectionError(ec.message(), "READ_ERROR");
  return module;
}

using DllCache = std::map<lfs::UniqueID, std::variant<size_t, InspectionError>>;

size_t inspectDll(const fs::path &path, DllCache &cache, std::vector<Module> &modules) {
  auto id = identity(path);
  if (auto it = cache.find(id); it != cache.end()) {
    if (auto *error = std::get_if<InspectionError>(&it->second))
      throw *error;
    return std::get<size_t>(it->second);
  }
  try {
    auto module = load(path);
    if (!module.dll)
      throw InspectionError("expected a DLL image", "NOT_DLL");
    size_t index = modules.size();
    modules.push_back(std::move(module));
    cache.emplace(id, index);
    return index;
  } catch (const InspectionError &e) {
    cache.emplace(id, e);
    throw;
  }
}

// Compute requiredness after discovery. A direct path can be discovered after
// a delay-only path to the very same module.
void markRequired(Report &report) {
  std::vector<std::vector<size_t>> outgoing(report.modules.size());
  for (size_t i = 0; i < report.dependencies.size(); ++i)
    outgoing[report.dependencies[i].importer].push_back(i);
  std::vector<bool> reached(report.modules.size());
  std::vector<size_t> pending{0};
  reached[0] = true;
  while (!pending.empty()) {
    size_t source = pending.back();
    pending.pop_back();
    for (size_t i : outgoing[source]) {
      auto &edge = report.dependencies[i];
      if (report.modules[source].imports[edge.importIndex].delayed)
        continue;
      edge.required = true;
      if (edge.target && !reached[*edge.target]) {
        reached[*edge.target] = true;
        pending.push_back(*edge.target);
      }
      if (edge.status != "resolved" && edge.status != "external_api")
        report.strictFailure = true;
    }
  }
}
} // namespace

Report inspect(const fs::path &root, const std::vector<fs::path> &searchPaths) {
  Report report;
  DllCache visited;
  std::map<fs::path, Directory> directories;
  auto rootId = identity(root);
  report.modules.push_back(load(root));
  if (report.modules.front().dll)
    visited.emplace(rootId, size_t{0});
  else
    visited.emplace(rootId, InspectionError("expected a DLL image", "NOT_DLL"));
  for (size_t i = 0; i < report.modules.size(); ++i) {
    for (size_t j = 0; j < report.modules[i].imports.size(); ++j) {
      Dependency edge{};
      edge.importer = i;
      edge.importIndex = j;
      locate(edge, report.modules[i].imports[j], report.modules[i].path.parent_path(), searchPaths,
             directories);
      if (!edge.path.empty()) {
        try {
          edge.target = inspectDll(edge.path, visited, report.modules);
          edge.status = "resolved";
          if (edge.kind == "unknown")
            edge.kind = "application";
        } catch (const InspectionError &e) {
          edge.architecture = e.architecture;
          if (e.code == "READ_ERROR")
            issue(edge, "inaccessible", "DLL_READ_ERROR", e.what());
          else
            issue(edge, "incompatible",
                  e.code == "UNSUPPORTED_ARCHITECTURE" ? "DLL_ARCH_MISMATCH" : "DLL_INVALID_IMAGE",
                  e.what());
        }
      }
      report.dependencies.push_back(std::move(edge));
    }
  }
  markRequired(report);
  return report;
}
} // namespace forge
