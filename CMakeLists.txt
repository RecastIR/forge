cmake_minimum_required(VERSION 3.20)
project(Forge LANGUAGES C CXX)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Using LLVM ${LLVM_PACKAGE_VERSION}")
add_executable(forge src/main.cpp src/pe.cpp src/dependencies.cpp src/report.cpp)
target_compile_features(forge PRIVATE cxx_std_20)
set_target_properties(forge PROPERTIES CXX_EXTENSIONS OFF)
target_include_directories(forge SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
target_compile_options(forge PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(forge PRIVATE LLVMObject)

include(CTest)
if(BUILD_TESTING)
  find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)
  foreach(tool llvm-mc lld-link llvm-dlltool llvm-readobj)
    find_program(${tool} NAMES ${tool} HINTS "${LLVM_TOOLS_BINARY_DIR}" REQUIRED)
  endforeach()
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
