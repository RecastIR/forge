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
# Resolve target locations before escaping them. Each plain-text input changes only
# when its configuration changes, including after reconfiguring an existing tree.
set(settings_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/$<CONFIG>")
set(startup "$<TARGET_FILE:forge_startup>")
set(runtime "$<TARGET_FILE:forge_runtime>")
foreach(setting llvm_bin startup runtime executable_sdk executable_link_flags)
  file(GENERATE OUTPUT "${settings_dir}/${setting}.txt" CONTENT "${${setting}}")
  list(APPEND settings_inputs "${settings_dir}/${setting}.txt")
endforeach()
add_custom_command(OUTPUT "${settings_dir}/executable_tools.inc"
  COMMAND "${CMAKE_COMMAND}" "-Ddirectory=${settings_dir}"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/executable_tools.cmake"
  DEPENDS ${settings_inputs} "${CMAKE_CURRENT_SOURCE_DIR}/executable_tools.cmake" VERBATIM)
add_custom_target(forge_executable_settings DEPENDS "${settings_dir}/executable_tools.inc")
add_dependencies(forge forge_executable_settings)
# Xcode requires the same translation unit in every configuration. Keeping this
# generated definition separate also allows linting the CLI immediately after configure.
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/executable_tools.cpp" CONTENT "#include \"executable_tools.inc\"\n")
target_sources(forge PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/executable_tools.cpp")
target_include_directories(forge PRIVATE "${settings_dir}")
configure_forge_cxx(forge)
