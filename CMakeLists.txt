cmake_minimum_required(VERSION 3.20)
file(REAL_PATH "${CMAKE_CURRENT_SOURCE_DIR}" source_dir)
file(REAL_PATH "${CMAKE_CURRENT_BINARY_DIR}" binary_dir)
if(source_dir STREQUAL binary_dir)
  message(FATAL_ERROR "Forge requires an out-of-source build. From the source directory run\n  cmake -S . -B build")
endif()
project(Forge LANGUAGES C CXX)

include(cmake/llvm.cmake)
foreach(action format format-check format-audit)
  add_custom_target(${action}
    COMMAND "${CMAKE_COMMAND}" "-DACTION=${action}" "-DLLVM_DIR=${LLVM_DIR}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/quality.cmake"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" VERBATIM)
endforeach()
option(FORGE_ENABLE_SANITIZERS "Build Forge with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
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
add_library(forge_core STATIC
  src/diagnostic.cpp
  src/pe/input.cpp src/pe/pe.cpp src/pe/dependencies.cpp
  src/analysis/analysis.cpp
  src/lift/integer.cpp src/lift/lift.cpp
  src/output/publication.cpp)
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

add_executable(forge src/cli/main.cpp src/cli/report.cpp src/cli/analysis_report.cpp
  src/cli/diagnostic.cpp)
set_target_properties(forge PROPERTIES LINK_LIBRARIES_STRATEGY REORDER_FREELY)
target_link_libraries(forge PRIVATE forge_core)
configure_forge_cxx(forge)

include(CTest)
if(BUILD_TESTING OR CMAKE_EXPORT_COMPILE_COMMANDS OR DEFINED FORGE_DIFFERENTIAL_IR)
  add_subdirectory(tests)
endif()
