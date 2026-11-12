add_library(forge_native_harness OBJECT support/native_harness.cpp)
configure_forge_cxx(forge_native_harness)
if(APPLE)
  set_target_properties(forge_native_harness PROPERTIES OSX_ARCHITECTURES arm64)
endif()
if(DEFINED FORGE_DIFFERENTIAL_IR)
  if(NOT APPLE OR NOT LLVM_VERSION_MAJOR EQUAL 17)
    message(FATAL_ERROR "Differential harness compilation requires macOS and LLVM 17")
  endif()
  set(object "${CMAKE_CURRENT_BINARY_DIR}/lifted.o")
  add_custom_command(OUTPUT "${object}"
    COMMAND "${LLVM_TOOLS_BINARY_DIR}/opt" -passes=verify -disable-output "${FORGE_DIFFERENTIAL_IR}"
    COMMAND "${LLVM_TOOLS_BINARY_DIR}/llc" -filetype=obj "${FORGE_DIFFERENTIAL_IR}" -o "${object}"
    DEPENDS "${FORGE_DIFFERENTIAL_IR}" VERBATIM)
  add_executable(differential_decimal_pairs EXCLUDE_FROM_ALL support/decimal_pairs.cpp "${object}")
  configure_forge_cxx(differential_decimal_pairs)
  set_target_properties(differential_decimal_pairs PROPERTIES OSX_ARCHITECTURES arm64
    RUNTIME_OUTPUT_DIRECTORY "$<1:${CMAKE_BINARY_DIR}/bin>")
  target_link_options(differential_decimal_pairs PRIVATE ${sanitizer_link_flags})
elseif(CMAKE_EXPORT_COMPILE_COMMANDS)
  add_library(decimal_pairs OBJECT EXCLUDE_FROM_ALL support/decimal_pairs.cpp)
  configure_forge_cxx(decimal_pairs)
  if(APPLE)
    set_target_properties(decimal_pairs PROPERTIES OSX_ARCHITECTURES arm64)
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
add_test(NAME windows_reference_runner COMMAND "${Python3_EXECUTABLE}" -B
  "${CMAKE_CURRENT_SOURCE_DIR}/differential/reference/test_runner.py")
add_test(NAME windows_differential_runner COMMAND "${Python3_EXECUTABLE}" -B
  "${CMAKE_CURRENT_SOURCE_DIR}/differential/test_differential.py")
foreach(tool llvm-mc lld-link llvm-dlltool llvm-readobj clang opt llc)
  if(EXISTS "${CMAKE_BINARY_DIR}/CMakeCache.txt" AND NOT FORGE_FIXTURE_LLVM_DIR STREQUAL LLVM_DIR)
    unset(${tool} CACHE)
  endif()
  find_program(${tool} NAMES ${tool} HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
endforeach()
set(FORGE_FIXTURE_LLVM_DIR "${LLVM_DIR}" CACHE INTERNAL "LLVM package used for fixture tools")
add_test(NAME build_config COMMAND "${Python3_EXECUTABLE}" -B
  "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_build.py" "${PROJECT_SOURCE_DIR}" "${CMAKE_COMMAND}" "${LLVM_DIR}")
set(fixtures "${PROJECT_BINARY_DIR}/fixtures")
add_test(NAME fixtures COMMAND "${Python3_EXECUTABLE}" -B
  "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/generate.py" "${fixtures}"
  --mc "${llvm-mc}" --link "${lld-link}" --dlltool "${llvm-dlltool}" --clang "${clang}")
set_tests_properties(fixtures PROPERTIES FIXTURES_SETUP pe_images)
foreach(suite metadata dependencies malformed cli discovery lift)
  set(script test_inspect.py)
  if(suite MATCHES "^(discovery|lift)$")
    set(script test_functions.py)
  endif()
  add_test(NAME ${suite} COMMAND "${Python3_EXECUTABLE}" -B
    "${CMAKE_CURRENT_SOURCE_DIR}/integration/${script}" ${suite}
    "$<TARGET_FILE:forge>" "${fixtures}" "${llvm-readobj}")
  set_tests_properties(${suite} PROPERTIES FIXTURES_REQUIRED pe_images TIMEOUT 90)
endforeach()
set(harness_linker "${CMAKE_CXX_COMPILER}" ${sanitizer_link_flags})
if(APPLE)
  set(sdk "${CMAKE_OSX_SYSROOT}")
  if(NOT sdk)
    set(sdk macosx)
  endif()
  # Xcode's compiler needs an SDK even when it is invoked directly by CTest.
  list(PREPEND harness_linker xcrun --sdk "${sdk}")
  list(APPEND harness_linker -arch arm64)
  if(CMAKE_OSX_DEPLOYMENT_TARGET)
    list(APPEND harness_linker "-mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
  endif()
endif()
foreach(mode codegen native differential)
  add_test(NAME ${mode} COMMAND "${Python3_EXECUTABLE}" -B
    "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_native.py" ${mode} "$<TARGET_FILE:forge>" "${fixtures}"
    "${opt}" "${llc}" "${llvm-readobj}" "$<TARGET_OBJECTS:forge_native_harness>" ${harness_linker})
  set_tests_properties(${mode} PROPERTIES FIXTURES_REQUIRED pe_images SKIP_RETURN_CODE 77 TIMEOUT 180)
endforeach()
