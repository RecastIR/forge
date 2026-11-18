add_library(forge_runtime STATIC
  src/core/runtime.cpp
  src/core/registration.cpp
  src/core/guest_memory.cpp
  src/compat/crt/msvcrt.cpp
  src/compat/crt/process_heap.cpp
  src/compat/crt/crt_parameters.cpp
  src/compat/win32/services.cpp
  src/compat/win32/console.cpp
  src/compat/win32/standard_handles.cpp
  src/core/process.cpp
  src/compat/win32/process_parameters.cpp)
target_include_directories(forge_runtime PUBLIC include)
find_package(Threads REQUIRED)
target_link_libraries(forge_runtime PRIVATE Threads::Threads)
target_link_options(forge_runtime INTERFACE ${sanitizer_link_flags})
configure_forge_output(forge_runtime ARCHIVE_OUTPUT_DIRECTORY LIBRARY_OUTPUT_PATH)
configure_forge_cxx(forge_runtime)

# Link this archive only when the translated PE supplies the executable's entry.
add_library(forge_startup STATIC src/startup.cpp)
target_link_libraries(forge_startup PUBLIC forge_runtime)
configure_forge_output(forge_startup ARCHIVE_OUTPUT_DIRECTORY LIBRARY_OUTPUT_PATH)
configure_forge_cxx(forge_startup)
