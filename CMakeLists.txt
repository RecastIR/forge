cmake_minimum_required(VERSION 3.20)
file(REAL_PATH "${CMAKE_CURRENT_SOURCE_DIR}" source_dir)
file(REAL_PATH "${CMAKE_CURRENT_BINARY_DIR}" binary_dir)
if(source_dir STREQUAL binary_dir)
  message(FATAL_ERROR "Forge requires an out-of-source build. From the source directory run\n  cmake -S . -B build")
endif()
project(Forge LANGUAGES C CXX)

if(APPLE AND NOT LLVM_DIR AND NOT DEFINED ENV{LLVM_DIR})
  execute_process(COMMAND brew --prefix llvm@17 OUTPUT_VARIABLE brew_llvm_prefix
                  OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
endif()
find_package(LLVM REQUIRED CONFIG HINTS ${brew_llvm_prefix})
message(STATUS "Using LLVM ${LLVM_PACKAGE_VERSION}")
add_executable(forge src/main.cpp src/pe.cpp src/dependencies.cpp src/report.cpp)
target_compile_features(forge PRIVATE cxx_std_20)
set_target_properties(forge PROPERTIES CXX_EXTENSIONS OFF)
target_include_directories(forge SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
target_compile_options(forge PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(forge PRIVATE LLVMObject)

option(FORGE_ENABLE_SANITIZERS "Build Forge with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
if(FORGE_ENABLE_SANITIZERS)
  target_compile_options(forge PRIVATE -fsanitize=address,undefined -fno-sanitize-recover=all
                                       -fno-omit-frame-pointer)
  target_link_options(forge PRIVATE -fsanitize=address,undefined)
endif()

include(CTest)
if(BUILD_TESTING)
  find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)
  foreach(tool llvm-mc lld-link llvm-dlltool llvm-readobj)
    if(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/CMakeCache.txt" AND NOT FORGE_FIXTURE_LLVM_DIR STREQUAL LLVM_DIR)
      unset(${tool} CACHE)
    endif()
    find_program(${tool} NAMES ${tool} HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
  endforeach()
  set(FORGE_FIXTURE_LLVM_DIR "${LLVM_DIR}" CACHE INTERNAL "LLVM package used for fixture tools")
  add_test(NAME build_config COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_build.py" "${CMAKE_COMMAND}" "${LLVM_DIR}")
  set(fixtures "${CMAKE_CURRENT_BINARY_DIR}/fixtures")
  add_test(NAME fixtures COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/generate.py" "${fixtures}"
    --mc "${llvm-mc}" --link "${lld-link}" --dlltool "${llvm-dlltool}")
  set_tests_properties(fixtures PROPERTIES FIXTURES_SETUP pe_images)
  foreach(suite metadata dependencies malformed cli)
    add_test(NAME ${suite} COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_inspect.py" ${suite}
      "$<TARGET_FILE:forge>" "${fixtures}" "${llvm-readobj}")
    set_tests_properties(${suite} PROPERTIES FIXTURES_REQUIRED pe_images TIMEOUT 90)
  endforeach()
endif()
