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
include(cmake/dependencies.cmake)
project(Forge LANGUAGES C CXX)

include(cmake/llvm.cmake)
forge_check_dependencies()
foreach(action format format-check format-audit)
  add_custom_target(${action}
    COMMAND "${CMAKE_COMMAND}" "-DACTION=${action}" "-DLLVM_DIR=${LLVM_DIR}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/quality.cmake"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" VERBATIM)
endforeach()
if(FORGE_PRESET STREQUAL "lint")
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

function(configure_forge_cxx target)
  target_compile_features(${target} PRIVATE cxx_std_20)
  set_target_properties(${target} PROPERTIES CXX_EXTENSIONS OFF)
  if(CMAKE_CXX_COMPILER_ID MATCHES "^(AppleClang|Clang|GNU)$" AND NOT MSVC)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
  endif()
  target_compile_options(${target} PRIVATE ${sanitizer_compile_flags})
endfunction()

function(configure_forge_output target property legacy_directory)
  set(properties "${property}")
  foreach(config IN LISTS CMAKE_CONFIGURATION_TYPES CMAKE_BUILD_TYPE)
    string(TOUPPER "${config}" config)
    if(DEFINED CMAKE_${property}_${config})
      list(APPEND properties "${property}_${config}")
    endif()
  endforeach()

  foreach(name IN LISTS properties)
    if(DEFINED CMAKE_${name})
      set(directory "${CMAKE_${name}}")
    else()
      set(directory "${legacy_directory}")
    endif()
    # These targets used to live at the project root. Leave a leading generator
    # expression to CMake because its result may be an absolute path.
    if(NOT IS_ABSOLUTE "${directory}" AND NOT directory MATCHES "^\\$<")
      set(directory "${PROJECT_BINARY_DIR}/${directory}")
    endif()
    set_property(TARGET ${target} PROPERTY ${name} "${directory}")
  endforeach()
endfunction()

add_subdirectory(compiler)
if(FORGE_BUILD_CLI)
  add_subdirectory(cli)
endif()

include(CTest)
if(BUILD_TESTING OR CMAKE_EXPORT_COMPILE_COMMANDS OR DEFINED FORGE_DIFFERENTIAL_IR OR DEFINED FORGE_DIFFERENTIAL_CASES)
  add_subdirectory(tests)
endif()
