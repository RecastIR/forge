add_executable(forge
  src/main.cpp src/parsing.cpp src/analysis_input.cpp
  src/commands/inspect.cpp src/commands/analyze.cpp
  src/commands/lift.cpp src/commands/lift_execution.cpp
  src/report.cpp src/analysis_report.cpp src/diagnostic.cpp)
target_include_directories(forge PRIVATE src)
configure_forge_output(forge RUNTIME_OUTPUT_DIRECTORY EXECUTABLE_OUTPUT_PATH)
set_target_properties(forge PROPERTIES LINK_LIBRARIES_STRATEGY REORDER_FREELY)
# LLVM can expose a global include directory containing a different CLI11.
target_link_libraries(forge PRIVATE CLI11::CLI11 forge_core)
add_dependencies(forge forge_startup forge_runtime)
target_compile_definitions(forge PRIVATE
  FORGE_LLVM_TOOLS="${llvm_bin}"
  FORGE_STARTUP_ARCHIVE="$<TARGET_FILE:forge_startup>"
  FORGE_RUNTIME_ARCHIVE="$<TARGET_FILE:forge_runtime>"
  FORGE_MACOS_SDK="${CMAKE_OSX_SYSROOT}"
  FORGE_MACOS_DEPLOYMENT_TARGET="${CMAKE_OSX_DEPLOYMENT_TARGET}"
  FORGE_SANITIZED_RUNTIME=$<BOOL:${FORGE_ENABLE_SANITIZERS}>)
configure_forge_cxx(forge)
