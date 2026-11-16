cmake_minimum_required(VERSION 3.20)
file(REAL_PATH "${CMAKE_CURRENT_SOURCE_DIR}" source_dir)
file(REAL_PATH "${CMAKE_CURRENT_BINARY_DIR}" binary_dir)
if(source_dir STREQUAL binary_dir)
  message(FATAL_ERROR "Forge requires an out-of-source build. Use make provision PRESET=dev, then cmake --preset dev.")
endif()
set(FORGE_BUILD_ROOT "${source_dir}/build" CACHE PATH "Parent directory for Forge build output")
file(REAL_PATH "${FORGE_BUILD_ROOT}" build_root)
file(REAL_PATH "${source_dir}/build" default_build_root)
if(binary_dir STREQUAL default_build_root OR binary_dir STREQUAL build_root)
  message(FATAL_ERROR "The build root is a container. Configure a child with cmake --preset dev. "
    "Save any existing artifacts and retire the old root CMake cache separately.")
endif()
option(FORGE_RUNTIME_ONLY "Build only the independently linkable Forge Runtime and its tests" OFF)
function(reject_managed_runtime_only)
  # Failed configures save command-line overrides. Restore the managed mode for a bare retry.
  if(DEFINED CACHE{FORGE_RUNTIME_ONLY})
    set_property(CACHE FORGE_RUNTIME_ONLY PROPERTY VALUE OFF)
  endif()
  message(FATAL_ERROR "FORGE_RUNTIME_ONLY requires a separate build directory without a Forge preset or provisioned toolchain.")
endfunction()
if(FORGE_RUNTIME_ONLY)
  if(FORGE_PRESET OR FORGE_CONFIGURED_PRESET OR FORGE_CONAN_PRESET)
    reject_managed_runtime_only()
  endif()
else()
  include(cmake/dependencies.cmake)
endif()
project(Forge LANGUAGES C CXX)

if(FORGE_RUNTIME_ONLY)
  # A fresh direct configure can select a Forge toolchain first loaded by project().
  if(FORGE_CONAN_PRESET)
    reject_managed_runtime_only()
  endif()
  option(FORGE_ENABLE_SANITIZERS "Build Forge with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
  set(FORGE_RUNTIME_IR_TOOLS_DIR "" CACHE PATH "Directory containing opt and llc for the optional ARM64 runtime IR test")
else()
  include(cmake/llvm.cmake)
  forge_check_dependencies()
endif()
foreach(action format format-check format-audit)
  add_custom_target(${action}
    COMMAND "${CMAKE_COMMAND}" "-DACTION=${action}" "-DLLVM_DIR=${LLVM_DIR}"
            "-DFORGE_RUNTIME_ONLY=${FORGE_RUNTIME_ONLY}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/quality.cmake"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" VERBATIM)
endforeach()
if(NOT FORGE_RUNTIME_ONLY AND FORGE_PRESET STREQUAL "lint")
  add_custom_target(lint
    COMMAND "${CMAKE_COMMAND}" -DACTION=lint "-DLLVM_DIR=${LLVM_DIR}"
            "-DLINT_DATABASE=${CMAKE_BINARY_DIR}/compile_commands.json"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/quality.cmake"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" VERBATIM)
endif()
if(FORGE_ENABLE_SANITIZERS)
  set(sanitizer_link_flags -fsanitize=address,undefined)
  set(sanitizer_compile_flags ${sanitizer_link_flags} -fno-sanitize-recover=all -fno-omit-frame-pointer)
  include(CheckCXXSourceCompiles)
  function(check_sanitizers)
    set(CMAKE_TRY_COMPILE_TARGET_TYPE EXECUTABLE)
    string(JOIN " " CMAKE_REQUIRED_FLAGS ${sanitizer_compile_flags})
    set(CMAKE_REQUIRED_LINK_OPTIONS ${sanitizer_link_flags})
    # Toolchain, architecture or SDK may have changed since the previous configure.
    unset(FORGE_SANITIZERS_SUPPORTED CACHE)
    check_cxx_source_compiles("int main(int argc, char** argv) { return argv[argc] != nullptr; }"
      FORGE_SANITIZERS_SUPPORTED FAIL_REGEX "argument unused|unknown argument|ignoring unknown option")
    if(NOT FORGE_SANITIZERS_SUPPORTED)
      message(FATAL_ERROR "FORGE_ENABLE_SANITIZERS requires a compiler and runtime that compile and link with ASan and UBSan. Check the selected compiler, architecture and SDK, or configure with -DFORGE_ENABLE_SANITIZERS=OFF.")
    endif()
  endfunction()
  check_sanitizers()
endif()

function(configure_forge_native target language standard)
  target_compile_features(${target} PRIVATE ${standard})
  set_target_properties(${target} PROPERTIES ${language}_EXTENSIONS OFF)
  if(CMAKE_${language}_COMPILER_ID MATCHES "^(AppleClang|Clang|GNU)$" AND NOT MSVC)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
  endif()
  target_compile_options(${target} PRIVATE ${sanitizer_compile_flags})
endfunction()

function(configure_forge_cxx target)
  configure_forge_native(${target} CXX cxx_std_20)
endfunction()

function(configure_forge_output target property legacy_variable)
  set(properties "${property}")
  if(NOT DEFINED CMAKE_${property} AND NOT "${${legacy_variable}}" STREQUAL "")
    # Keep the legacy setting in the component's directory scope. CMake treats
    # its path literally even when it contains "$<".
    cmake_path(ABSOLUTE_PATH ${legacy_variable} BASE_DIRECTORY "${PROJECT_BINARY_DIR}"
      OUTPUT_VARIABLE directory)
    set(${legacy_variable} "${directory}" PARENT_SCOPE)
    set(properties "")
  endif()
  foreach(config IN LISTS CMAKE_CONFIGURATION_TYPES CMAKE_BUILD_TYPE)
    string(TOUPPER "${config}" config)
    if(DEFINED CMAKE_${property}_${config})
      list(APPEND properties "${property}_${config}")
    endif()
  endforeach()

  foreach(name IN LISTS properties)
    set(directory "${CMAKE_${name}}")
    # These targets used to live at the project root. Leave a leading generator
    # expression to CMake because its result may be an absolute path.
    if(NOT IS_ABSOLUTE "${directory}" AND NOT directory MATCHES "^\\$<")
      set_property(TARGET ${target} PROPERTY ${name} "${PROJECT_BINARY_DIR}/${directory}")
    endif()
  endforeach()
endfunction()

add_subdirectory(runtime)
if(NOT FORGE_RUNTIME_ONLY)
  add_subdirectory(compiler)
  if(FORGE_BUILD_CLI)
    add_subdirectory(cli)
  endif()
endif()

include(CTest)
if(BUILD_TESTING OR CMAKE_EXPORT_COMPILE_COMMANDS OR DEFINED FORGE_DIFFERENTIAL_IR OR DEFINED FORGE_DIFFERENTIAL_CASES)
  add_subdirectory(tests)
endif()
