add_library(forge_core STATIC
  src/diagnostic.cpp
  src/pe/input.cpp src/pe/pe.cpp src/pe/dependencies.cpp
  src/analysis/analysis.cpp
  src/lift/address_fact.cpp src/lift/cfg.cpp src/lift/jump_table.cpp src/lift/recovery.cpp src/lift/leaf_recovery.cpp src/lift/call_flow.cpp
  src/lift/operands.cpp src/lift/group_analysis.cpp src/lift/execution_context.cpp
  src/lift/integer.cpp src/lift/memory.cpp src/lift/image_memory.cpp src/lift/lift.cpp
  src/output/publication.cpp)
set_target_properties(forge_core PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
target_include_directories(forge_core PUBLIC src)
target_include_directories(forge_core SYSTEM PUBLIC ${LLVM_INCLUDE_DIRS})
target_link_libraries(forge_core PUBLIC LLVMDebugInfoDWARF LLVMObject LLVMTransformUtils LLVMCore
  LLVMX86Disassembler LLVMX86Desc LLVMX86Info)
target_link_options(forge_core INTERFACE ${sanitizer_link_flags})
if(APPLE AND TARGET LTO)
  # The release archive contains ThinLTO objects. Use the matching LLVM bitcode reader.
  target_link_options(forge_core INTERFACE "LINKER:-lto_library,$<TARGET_FILE:LTO>")
endif()
configure_forge_cxx(forge_core)

if(FORGE_BUILD_CLI)
  add_executable(forge
    src/cli/main.cpp src/cli/parsing.cpp src/cli/analysis_input.cpp
    src/cli/commands/inspect.cpp src/cli/commands/analyze.cpp
    src/cli/commands/lift.cpp src/cli/commands/lift_execution.cpp
    src/cli/report.cpp src/cli/analysis_report.cpp src/cli/diagnostic.cpp)
  set_target_properties(forge PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}"
    LINK_LIBRARIES_STRATEGY REORDER_FREELY)
  # LLVM can expose a global include directory containing a different CLI11.
  target_link_libraries(forge PRIVATE CLI11::CLI11 forge_core)
  configure_forge_cxx(forge)
endif()
