add_library(forge_runtime STATIC
  src/core/runtime.cpp
  src/core/registration.cpp
  src/core/guest_memory.cpp
  src/core/page_protection.cpp
  src/core/image_query.cpp
  src/compat/win32/virtual_query.cpp
  src/compat/win32/virtual_protect.cpp
  src/core/heap.cpp
  src/compat/process_state.cpp
  src/compat/crt/standard_streams.cpp
  src/compat/crt/format.cpp
  src/compat/crt/fatal.cpp
  src/compat/crt/initterm.cpp
  src/compat/crt/termination.cpp
  src/compat/crt/msvcrt.cpp
  src/compat/crt/process_heap.cpp
  src/compat/crt/crt_parameters.cpp
  src/compat/win32/startup_info.cpp
  src/compat/win32/services.cpp
  src/compat/win32/console.cpp
  src/compat/win32/standard_handles.cpp
  src/platform/darwin/io.cpp
  src/platform/darwin/wait.cpp
  src/managed_process.cpp
  src/core/process.cpp
  src/compat/win32/process_parameters.cpp)
# The sleep adapter test links its own copy of wait.cpp with controlled host calls.
set_source_files_properties(src/platform/darwin/wait.cpp PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)
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
