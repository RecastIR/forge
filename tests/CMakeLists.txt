if(BUILD_TESTING OR CMAKE_EXPORT_COMPILE_COMMANDS)
  find_package(Threads REQUIRED)
  # Build a second copy of the checked operation with a latch immediately before transfer.
  # The renamed symbols leave every ordinary contract test linked to the production archive.
  add_library(runtime_transfer_probe OBJECT EXCLUDE_FROM_ALL ../runtime/src/guest_memory.cpp)
  target_link_libraries(runtime_transfer_probe PRIVATE forge_runtime)
  target_compile_definitions(runtime_transfer_probe PRIVATE FORGE_RUNTIME_TEST_TRANSFER
    forge_rt_read_guest=forgeTestReadGuest forge_rt_write_guest=forgeTestWriteGuest
    forge_rt_validate_guest=forgeTestValidateGuest
    forge_rt_report_scalar_boundary=forgeTestReportScalarBoundary)
  configure_forge_cxx(runtime_transfer_probe)
  add_executable(runtime_contract unit/runtime.cpp unit/runtime_memory.cpp unit/runtime_process.cpp
    unit/runtime_console_process.cpp unit/runtime_write.cpp
    $<TARGET_OBJECTS:runtime_transfer_probe>)
  target_link_libraries(runtime_contract PRIVATE forge_runtime Threads::Threads)
  configure_forge_cxx(runtime_contract)

  add_executable(runtime_c_smoke integration/runtime_smoke.c)
  target_link_libraries(runtime_c_smoke PRIVATE forge_runtime)
  configure_forge_native(runtime_c_smoke C c_std_11)

  add_executable(runtime_benchmark EXCLUDE_FROM_ALL benchmarks/runtime_calls.cpp benchmarks/runtime_direct.cpp)
  target_link_libraries(runtime_benchmark PRIVATE forge_runtime)
  configure_forge_cxx(runtime_benchmark)
  # Keep the direct baseline in a separate translation unit from the timed loop.
  set_target_properties(runtime_benchmark PROPERTIES UNITY_BUILD OFF INTERPROCEDURAL_OPTIMIZATION OFF)
  foreach(config IN LISTS CMAKE_CONFIGURATION_TYPES CMAKE_BUILD_TYPE)
    string(TOUPPER "${config}" upper_config)
    set_property(TARGET runtime_benchmark PROPERTY INTERPROCEDURAL_OPTIMIZATION_${upper_config} OFF)
  endforeach()

  if(BUILD_TESTING)
    add_test(NAME runtime_contract COMMAND runtime_contract)
    set_tests_properties(runtime_contract PROPERTIES TIMEOUT 60)
    add_test(NAME runtime_c_smoke COMMAND runtime_c_smoke)
  else()
    set_target_properties(runtime_contract runtime_c_smoke PROPERTIES EXCLUDE_FROM_ALL ON)
  endif()

  # Core-only and standalone runtime builds can use a reduced LLVM tool package.
  function(find_optional_arm64_tools directory)
    foreach(tool opt llc)
      execute_process(COMMAND "${directory}/${tool}" --version RESULT_VARIABLE result
        OUTPUT_VARIABLE banner ERROR_QUIET)
      if(NOT result STREQUAL "0" OR NOT banner MATCHES "LLVM version (23[.][0-9]+[.][0-9]+)([ \r\n]|$)")
        message(STATUS "Omitting optional ARM64 tests: expected a runnable LLVM 23 ${tool} in ${directory}")
        return()
      endif()
      set(${tool}_version "${CMAKE_MATCH_1}")
    endforeach()
    if(NOT opt_version STREQUAL llc_version OR NOT banner MATCHES "[ \t]aarch64[ \t]+-")
      message(STATUS "Omitting optional ARM64 tests: opt and ARM64-capable llc must have matching versions")
      return()
    endif()
    set(optional_opt "${directory}/opt" PARENT_SCOPE)
    set(optional_llc "${directory}/llc" PARENT_SCOPE)
  endfunction()

  if(BUILD_TESTING AND FORGE_RUNTIME_ONLY AND FORGE_RUNTIME_IR_TOOLS_DIR)
    find_optional_arm64_tools("${FORGE_RUNTIME_IR_TOOLS_DIR}")
  elseif(BUILD_TESTING AND NOT FORGE_RUNTIME_ONLY AND NOT FORGE_BUILD_CLI)
    find_optional_arm64_tools("${llvm_bin}")
  endif()

  function(add_runtime_ir_smoke)
    if(FORGE_RUNTIME_ONLY OR NOT FORGE_BUILD_CLI)
      if(NOT optional_llc)
        return()
      endif()
      set(opt "${optional_opt}")
      set(llc "${optional_llc}")
    else()
      forge_llvm_tool(opt)
      forge_llvm_tool(llc)
    endif()
    set(runtime_ir "${CMAKE_CURRENT_SOURCE_DIR}/integration/runtime_smoke.ll")
    set(runtime_obj "${CMAKE_CURRENT_BINARY_DIR}/runtime-ir/$<CONFIG>/runtime_smoke.o")
    add_custom_command(OUTPUT "${runtime_obj}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/runtime-ir/$<CONFIG>"
      COMMAND "${opt}" -passes=verify -disable-output "${runtime_ir}"
      COMMAND "${llc}" -filetype=obj "${runtime_ir}" -o "${runtime_obj}"
      DEPENDS "${runtime_ir}" "${opt}" "${llc}" VERBATIM)
    add_custom_target(runtime_ir_object DEPENDS "${runtime_obj}")
    add_executable(runtime_ir_smoke integration/runtime_ir_driver.c)
    add_dependencies(runtime_ir_smoke runtime_ir_object)
    target_link_libraries(runtime_ir_smoke PRIVATE "${runtime_obj}" forge_runtime)
    configure_forge_native(runtime_ir_smoke C c_std_11)
    add_test(NAME runtime_ir_smoke COMMAND runtime_ir_smoke)
  endfunction()

  set(runtime_arch "${CMAKE_OSX_ARCHITECTURES}")
  if(NOT runtime_arch)
    set(runtime_arch "${CMAKE_SYSTEM_PROCESSOR}")
  endif()
  if(BUILD_TESTING AND CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND NOT CMAKE_CROSSCOMPILING AND
     CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "arm64" AND runtime_arch STREQUAL "arm64")
    add_runtime_ir_smoke()
  endif()
  if(CMAKE_EXPORT_COMPILE_COMMANDS AND NOT TARGET runtime_ir_smoke)
    # Supply a real C compile command for the driver even on a host without the IR tools.
    add_library(runtime_ir_driver OBJECT EXCLUDE_FROM_ALL integration/runtime_ir_driver.c)
    target_link_libraries(runtime_ir_driver PRIVATE forge_runtime)
    configure_forge_native(runtime_ir_driver C c_std_11)
  endif()
endif()
if(FORGE_RUNTIME_ONLY)
  return()
endif()

add_library(forge_native_harness OBJECT support/native_harness.cpp)
configure_forge_cxx(forge_native_harness)
if(BUILD_TESTING OR CMAKE_EXPORT_COMPILE_COMMANDS)
  add_library(register_state_harness OBJECT support/register_state.cpp)
  configure_forge_cxx(register_state_harness)
  if(APPLE)
    set_target_properties(register_state_harness PROPERTIES OSX_ARCHITECTURES arm64)
    add_library(checked_memory_harness OBJECT support/checked_memory.cpp)
    target_link_libraries(checked_memory_harness PRIVATE forge_runtime)
    configure_forge_cxx(checked_memory_harness)
    set_target_properties(checked_memory_harness PROPERTIES OSX_ARCHITECTURES arm64)
    add_library(abi_service_harness OBJECT support/abi_services.cpp)
    target_link_libraries(abi_service_harness PRIVATE forge_runtime)
    configure_forge_cxx(abi_service_harness)
    set_target_properties(abi_service_harness PROPERTIES OSX_ARCHITECTURES arm64)
    add_library(string_service_harness OBJECT support/string_service.cpp)
    target_link_libraries(string_service_harness PRIVATE forge_runtime)
    configure_forge_cxx(string_service_harness)
    set_target_properties(string_service_harness PROPERTIES OSX_ARCHITECTURES arm64)
    add_library(process_harness OBJECT support/process.cpp)
    target_link_libraries(process_harness PRIVATE forge_runtime)
    configure_forge_cxx(process_harness)
    set_target_properties(process_harness PROPERTIES OSX_ARCHITECTURES arm64)
    add_executable(invalid_artifact support/invalid_artifact.c)
    target_link_libraries(invalid_artifact PRIVATE forge_startup)
    configure_forge_native(invalid_artifact C c_std_11)
  endif()
endif()
if(APPLE)
  set_target_properties(forge_native_harness PROPERTIES OSX_ARCHITECTURES arm64)
endif()
if(DEFINED FORGE_DIFFERENTIAL_IR OR DEFINED FORGE_DIFFERENTIAL_CASES OR CMAKE_EXPORT_COMPILE_COMMANDS)
  add_library(runtime_pairs OBJECT EXCLUDE_FROM_ALL support/runtime_pairs.cpp)
  target_link_libraries(runtime_pairs PRIVATE forge_runtime)
  foreach(harness decimal_pairs calculate_pairs)
    add_library(${harness} OBJECT EXCLUDE_FROM_ALL support/decimal_pairs.cpp)
  endforeach()
  foreach(harness decimal_pairs calculate_pairs runtime_pairs)
    configure_forge_cxx(${harness})
    if(APPLE)
      set_target_properties(${harness} PROPERTIES OSX_ARCHITECTURES arm64)
    endif()
  endforeach()
  target_compile_definitions(calculate_pairs PRIVATE FORGE_CALCULATE_PAIRS)
endif()
if(DEFINED FORGE_DIFFERENTIAL_IR OR DEFINED FORGE_DIFFERENTIAL_CASES)
  if(NOT APPLE)
    message(FATAL_ERROR "Differential harness compilation requires macOS")
  endif()
  forge_llvm_tool(opt)
  forge_llvm_tool(llc)

  function(add_differential_variant target harness ir variant output)
    set(object "${output}/tests/lifted.o")
    set(input_ir "${ir}")
    if(variant STREQUAL "o2")
      set(input_ir "${output}/tests/optimized.ll")
      get_filename_component(ir_directory "${ir}" DIRECTORY)
      get_filename_component(ir_name "${ir}" NAME)
      add_custom_command(OUTPUT "${input_ir}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${output}/tests"
        COMMAND "${opt}" -passes=verify -disable-output "${ir_name}"
        COMMAND "${opt}" "-passes=default<O2>" -S "${ir_name}" -o "${input_ir}"
        WORKING_DIRECTORY "${ir_directory}"
        DEPENDS "${ir}" VERBATIM)
    elseif(NOT variant STREQUAL "baseline")
      message(FATAL_ERROR "Select baseline or o2 for the differential IR variant")
    endif()
    add_custom_command(OUTPUT "${object}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${output}/tests"
      COMMAND "${opt}" -passes=verify -disable-output "${input_ir}"
      COMMAND "${llc}" -filetype=obj "${input_ir}" -o "${object}"
      DEPENDS "${input_ir}" VERBATIM)
    add_custom_target(${target}_objects DEPENDS "${object}")
    add_dependencies(${target}_objects ${harness})
    add_executable(${target} EXCLUDE_FROM_ALL $<TARGET_OBJECTS:${harness}>)
    if(XCODE)
      target_sources(${target} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/differential_link.cpp")
    endif()
    add_dependencies(${target} ${target}_objects)
    target_link_libraries(${target} PRIVATE "${object}")
    if(harness STREQUAL "runtime_pairs")
      target_link_libraries(${target} PRIVATE forge_runtime)
    endif()
    target_link_options(${target} PRIVATE ${sanitizer_link_flags})
    set_target_properties(${target} PROPERTIES OSX_ARCHITECTURES arm64
      OUTPUT_NAME "differential_${harness}" RUNTIME_OUTPUT_DIRECTORY "$<1:${output}/bin>")
  endfunction()

  if(XCODE)
    # Xcode needs a compilable source to link an executable.
    file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/differential_link.cpp" CONTENT "// Xcode link source.\n")
  endif()
  if(DEFINED FORGE_DIFFERENTIAL_CASES)
    foreach(entry IN LISTS FORGE_DIFFERENTIAL_CASES)
      if(NOT entry MATCHES "^([a-z][a-z0-9_]*)/([a-z][a-z0-9_]*):([a-z][a-z0-9_]*)$")
        message(FATAL_ERROR "Invalid differential case: ${entry}")
      endif()
      set(case_dir "${FORGE_DIFFERENTIAL_OUTPUT}/${CMAKE_MATCH_1}/${CMAKE_MATCH_2}")
      set(harness "${CMAKE_MATCH_3}")
      set(target_prefix "diff-${CMAKE_MATCH_1}-${CMAKE_MATCH_2}")
      foreach(variant baseline o2)
        add_differential_variant("${target_prefix}-${variant}" "${harness}" "${case_dir}/generated/lifted.ll"
          "${variant}" "${case_dir}/${variant}/native")
      endforeach()
    endforeach()
  else()
    if(NOT DEFINED FORGE_DIFFERENTIAL_VARIANT)
      set(FORGE_DIFFERENTIAL_VARIANT baseline)
    endif()
    if(NOT DEFINED FORGE_DIFFERENTIAL_HARNESS)
      set(FORGE_DIFFERENTIAL_HARNESS decimal_pairs)
    endif()
    add_differential_variant("differential_${FORGE_DIFFERENTIAL_HARNESS}" "${FORGE_DIFFERENTIAL_HARNESS}"
      "${FORGE_DIFFERENTIAL_IR}" "${FORGE_DIFFERENTIAL_VARIANT}" "${CMAKE_BINARY_DIR}")
  endif()
endif()
if(BUILD_TESTING OR CMAKE_EXPORT_COMPILE_COMMANDS)
  add_executable(integer_semantics unit/integer.cpp)
  add_executable(asm_info_lifetime unit/asm_info.cpp)
  add_executable(input_lifetime unit/input.cpp)
  add_executable(executable_contract unit/executable.cpp)
  add_executable(recovery_contract unit/recovery.cpp)
  target_include_directories(recovery_contract PRIVATE ../runtime/include)
  add_executable(lift_contract unit/lift.cpp)
  target_link_libraries(lift_contract PRIVATE LLVMAnalysis LLVMAsmParser)
  add_executable(lift_command unit/lift_command.cpp
    ../cli/src/commands/lift_execution.cpp ../cli/src/analysis_input.cpp ../cli/src/diagnostic.cpp)
  target_include_directories(lift_command PRIVATE ../cli/src)
  set_target_properties(integer_semantics lift_contract PROPERTIES LINK_LIBRARIES_STRATEGY REORDER_FREELY)
  target_link_libraries(integer_semantics PRIVATE LLVMAnalysis)
  foreach(target integer_semantics asm_info_lifetime input_lifetime executable_contract recovery_contract lift_contract lift_command)
    target_link_libraries(${target} PRIVATE forge_core)
    configure_forge_cxx(${target})
  endforeach()
  if(BUILD_TESTING)
    add_test(NAME integer_semantics COMMAND integer_semantics)
    add_test(NAME asm_info_lifetime COMMAND asm_info_lifetime)
  else()
    set_target_properties(integer_semantics asm_info_lifetime input_lifetime executable_contract recovery_contract lift_contract lift_command register_state_harness PROPERTIES EXCLUDE_FROM_ALL ON)
  endif()
endif()
if(NOT BUILD_TESTING)
  set_target_properties(forge_native_harness PROPERTIES EXCLUDE_FROM_ALL ON)
  return()
endif()

find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)
add_test(NAME windows_fixture_manifests COMMAND "${Python3_EXECUTABLE}" -B
  "${CMAKE_CURRENT_SOURCE_DIR}/differential/manifests.py")
add_test(NAME windows_fixture_manifest_validation COMMAND "${Python3_EXECUTABLE}" -B
  "${CMAKE_CURRENT_SOURCE_DIR}/differential/test_manifests.py")
add_test(NAME windows_fixture_shape COMMAND "${Python3_EXECUTABLE}" -B
  "${CMAKE_CURRENT_SOURCE_DIR}/differential/test_fixture_shape.py")
add_test(NAME windows_reference_runner COMMAND "${Python3_EXECUTABLE}" -B
  "${CMAKE_CURRENT_SOURCE_DIR}/differential/reference/test_runner.py")
add_test(NAME windows_differential_runner COMMAND "${Python3_EXECUTABLE}" -B
  "${CMAKE_CURRENT_SOURCE_DIR}/differential/test_differential.py")
add_test(NAME differential_coverage COMMAND "${Python3_EXECUTABLE}" -B
  "${CMAKE_CURRENT_SOURCE_DIR}/differential/test_coverage.py")
foreach(tool llvm-mc lld-link llvm-dlltool clang)
  forge_llvm_tool("${tool}")
endforeach()
set(build_test_toolchain "")
if(FORGE_BUILD_CLI)
  get_filename_component(build_test_toolchain "${CMAKE_TOOLCHAIN_FILE}" ABSOLUTE BASE_DIR "${PROJECT_BINARY_DIR}")
endif()
set(build_test_args
  "${PROJECT_SOURCE_DIR}" "${CMAKE_COMMAND}" "${LLVM_DIR}" "${llvm_bin}" "${FORGE_BUILD_ROOT}/tmp"
  "$<BOOL:${FORGE_BUILD_CLI}>" "$<1:${build_test_toolchain}>" "$<CONFIG>" "${CMAKE_GENERATOR}"
  "$<TARGET_EXISTS:runtime_ir_smoke>" "${PROJECT_BINARY_DIR}/fixtures/$<CONFIG>")
add_test(NAME build_config COMMAND "${Python3_EXECUTABLE}" -B
  "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_build.py" build ${build_test_args})
if(FORGE_BUILD_CLI)
  add_test(NAME build_provisioning COMMAND "${Python3_EXECUTABLE}" -B
    "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_build.py" provisioning ${build_test_args})
  set_tests_properties(build_provisioning PROPERTIES SKIP_RETURN_CODE 77)
endif()
if(llvm_version STREQUAL "23.1.5" AND EXISTS "${llvm_bin}/clang-format" AND EXISTS "${llvm_bin}/clang-tidy")
  add_test(NAME cpp_style COMMAND "${Python3_EXECUTABLE}" -B
    "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_style.py" "${PROJECT_SOURCE_DIR}" "${llvm_bin}" "${FORGE_BUILD_ROOT}/tmp")
endif()
set(fixtures "${PROJECT_BINARY_DIR}/fixtures/$<CONFIG>")
add_test(NAME fixtures COMMAND "${Python3_EXECUTABLE}" -B
  "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/generate.py" "${fixtures}"
  --mc "${llvm-mc}" --link "${lld-link}" --dlltool "${llvm-dlltool}" --clang "${clang}")
set_tests_properties(fixtures PROPERTIES FIXTURES_SETUP pe_images)
set_tests_properties(build_config PROPERTIES FIXTURES_REQUIRED pe_images)
add_test(NAME input_lifetime COMMAND input_lifetime "${fixtures}/minimal.exe")
add_test(NAME recovery_contract COMMAND recovery_contract "${fixtures}/stack.exe" "${fixtures}/leaves.exe" "${fixtures}/jump.exe" "${fixtures}/indirect.exe" "${fixtures}/last-error.exe")
add_test(NAME lift_contract COMMAND lift_contract "${fixtures}/add.exe" "${fixtures}/cfg.exe"
  "${fixtures}/image.exe" "${fixtures}/stack.exe")
add_test(NAME lift_command COMMAND lift_command "${fixtures}/add.exe")
set_tests_properties(input_lifetime recovery_contract lift_contract lift_command PROPERTIES FIXTURES_REQUIRED pe_images)
set(executable_test "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_executable.py")
add_test(NAME executable_contract COMMAND "${Python3_EXECUTABLE}" -B "${executable_test}" compiler
  "${fixtures}" "$<TARGET_FILE:executable_contract>")
set_tests_properties(executable_contract PROPERTIES FIXTURES_REQUIRED pe_images TIMEOUT 90)
if(FORGE_BUILD_CLI)
  foreach(tool llvm-readobj opt llc)
    forge_llvm_tool("${tool}")
  endforeach()
  set(object_tools "${opt}" "${llc}" "${llvm-readobj}")
elseif(optional_llc)
  execute_process(COMMAND "${llvm_bin}/llvm-readobj" --version RESULT_VARIABLE result OUTPUT_QUIET ERROR_QUIET)
  if(result STREQUAL "0")
    set(object_tools "${optional_opt}" "${optional_llc}" "${llvm_bin}/llvm-readobj")
  endif()
endif()
if(object_tools)
  add_test(NAME executable_object COMMAND "${Python3_EXECUTABLE}" -B "${executable_test}" object
    "${fixtures}" "$<TARGET_FILE:executable_contract>" ${object_tools})
  set_tests_properties(executable_object PROPERTIES FIXTURES_REQUIRED pe_images TIMEOUT 90)
endif()
if(NOT FORGE_BUILD_CLI)
  return()
endif()
add_test(NAME executable_readiness COMMAND "${Python3_EXECUTABLE}" -B
  "${executable_test}" readiness "${fixtures}" "$<TARGET_FILE:forge>")
set_tests_properties(executable_readiness PROPERTIES FIXTURES_REQUIRED pe_images TIMEOUT 90)
foreach(suite metadata dependencies malformed cli discovery lift guest_imports)
  set(script test_inspect.py)
  if(suite MATCHES "^(discovery|lift)$")
    set(script test_functions.py)
  elseif(suite STREQUAL "guest_imports")
    set(script test_imports.py)
  endif()
  add_test(NAME ${suite} COMMAND "${Python3_EXECUTABLE}" -B
    "${CMAKE_CURRENT_SOURCE_DIR}/integration/${script}" ${suite}
    "$<TARGET_FILE:forge>" "${fixtures}" "${llvm-readobj}")
  set_tests_properties(${suite} PROPERTIES FIXTURES_REQUIRED pe_images TIMEOUT 90)
endforeach()
set(harness_linker "${CMAKE_CXX_COMPILER}" ${executable_link_flags})
if(APPLE)
  # A compiler invoked directly by a harness build needs the selected SDK.
  list(PREPEND harness_linker xcrun --sdk "${executable_sdk}")
  list(APPEND harness_linker -arch arm64)
endif()
foreach(mode codegen native differential)
  add_test(NAME ${mode} COMMAND "${Python3_EXECUTABLE}" -B
    "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_native.py" ${mode} "$<TARGET_FILE:forge>" "${fixtures}"
    "${opt}" "${llc}" "${llvm-readobj}" "$<TARGET_OBJECTS:forge_native_harness>" ${harness_linker})
  set_tests_properties(${mode} PROPERTIES FIXTURES_REQUIRED pe_images SKIP_RETURN_CODE 77 TIMEOUT 180)
endforeach()

if(APPLE)
  add_test(NAME native_executable COMMAND "${Python3_EXECUTABLE}" -B
    "${executable_test}" native "${fixtures}" "$<TARGET_FILE:forge>" "$<TARGET_FILE:executable_contract>" "${opt}" "${llc}" "${llvm-readobj}"
    "$<TARGET_FILE:invalid_artifact>" "$<TARGET_OBJECTS:process_harness>"
    "$<TARGET_FILE:forge_startup>" "$<TARGET_FILE:forge_runtime>" "${executable_sdk}" ${executable_link_flags})
  set_tests_properties(native_executable PROPERTIES FIXTURES_REQUIRED pe_images SKIP_RETURN_CODE 77 TIMEOUT 180)
  foreach(memory_suite stack image jump indirect)
    add_test(NAME guest_${memory_suite} COMMAND "${Python3_EXECUTABLE}" -B
      "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_${memory_suite}.py" "$<TARGET_FILE:forge>" "${fixtures}/${memory_suite}.exe"
      "${opt}" "${llc}" "$<TARGET_OBJECTS:forge_native_harness>" "$<TARGET_OBJECTS:register_state_harness>" ${harness_linker})
    set_tests_properties(guest_${memory_suite} PROPERTIES FIXTURES_REQUIRED pe_images SKIP_RETURN_CODE 77 TIMEOUT 180)
  endforeach()
  set_tests_properties(guest_stack guest_image guest_jump guest_indirect PROPERTIES ENVIRONMENT "FORGE_TEST_LIFT_CONTRACT=$<TARGET_FILE:lift_contract>")
  set_property(TEST guest_jump guest_indirect APPEND PROPERTY ENVIRONMENT "LLVM_DIR=${LLVM_DIR}")
  add_test(NAME guest_checked_memory COMMAND "${Python3_EXECUTABLE}" -B
    "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_checked_memory.py" "$<TARGET_FILE:forge>"
    "${fixtures}/checked-memory.exe" "${opt}" "${llc}" "$<TARGET_OBJECTS:checked_memory_harness>"
    "$<TARGET_FILE:forge_runtime>" ${harness_linker})
  set_tests_properties(guest_checked_memory PROPERTIES FIXTURES_REQUIRED pe_images SKIP_RETURN_CODE 77 TIMEOUT 90)
  add_test(NAME guest_service_abi COMMAND "${Python3_EXECUTABLE}" -B
    "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_service_abi.py" "$<TARGET_FILE:forge>"
    "${fixtures}/service-abi.exe" "${opt}" "${llc}" "$<TARGET_FILE:lift_contract>"
    "$<TARGET_OBJECTS:string_service_harness>" "$<TARGET_OBJECTS:abi_service_harness>"
    "$<TARGET_FILE:forge_runtime>" ${harness_linker})
  set_tests_properties(guest_service_abi PROPERTIES FIXTURES_REQUIRED pe_images SKIP_RETURN_CODE 77 TIMEOUT 120)
  add_test(NAME guest_lstrlen COMMAND "${Python3_EXECUTABLE}" -B
    "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_lstrlen.py" "$<TARGET_FILE:forge>"
    "${fixtures}/lstrlen.exe" "${opt}" "${llc}" "$<TARGET_OBJECTS:string_service_harness>"
    "$<TARGET_FILE:forge_runtime>" "$<TARGET_FILE:lift_contract>" ${harness_linker})
  set_tests_properties(guest_lstrlen PROPERTIES FIXTURES_REQUIRED pe_images SKIP_RETURN_CODE 77 TIMEOUT 90)
  add_test(NAME guest_process COMMAND "${Python3_EXECUTABLE}" -B
    "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_process.py" "$<TARGET_FILE:forge>"
    "${fixtures}" "${opt}" "${llc}" "$<TARGET_FILE:lift_contract>" "$<TARGET_OBJECTS:process_harness>"
    "$<TARGET_OBJECTS:abi_service_harness>" "$<TARGET_FILE:forge_runtime>" ${harness_linker})
  set_tests_properties(guest_process PROPERTIES FIXTURES_REQUIRED pe_images SKIP_RETURN_CODE 77 TIMEOUT 120)
endif()
