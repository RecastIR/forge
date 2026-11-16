add_executable(forge
  src/main.cpp src/parsing.cpp src/analysis_input.cpp
  src/commands/inspect.cpp src/commands/analyze.cpp
  src/commands/lift.cpp src/commands/lift_execution.cpp
  src/report.cpp src/analysis_report.cpp src/diagnostic.cpp)
target_include_directories(forge PRIVATE src)
set_target_properties(forge PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}"
  LINK_LIBRARIES_STRATEGY REORDER_FREELY)
# LLVM can expose a global include directory containing a different CLI11.
target_link_libraries(forge PRIVATE CLI11::CLI11 forge_core)
configure_forge_cxx(forge)
