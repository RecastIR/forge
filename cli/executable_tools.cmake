cmake_minimum_required(VERSION 3.20)

function(cpp_string value result)
  string(REPLACE "\\" "\\\\" escaped "${value}")
  string(REPLACE "\"" "\\\"" escaped "${escaped}")
  string(REPLACE "\n" "\\n" escaped "${escaped}")
  string(REPLACE "\r" "\\r" escaped "${escaped}")
  string(REPLACE "\t" "\\t" escaped "${escaped}")
  set(${result} "\"${escaped}\"" PARENT_SCOPE)
endfunction()

foreach(setting llvm_bin startup runtime executable_sdk executable_link_flags)
  file(READ "${directory}/${setting}.txt" ${setting})
endforeach()
cpp_string("${llvm_bin}/opt" opt)
cpp_string("${llvm_bin}/llc" llc)
cpp_string("${startup}" startup)
cpp_string("${runtime}" runtime)
cpp_string("${executable_sdk}" sdk)
set(link_flags "")
foreach(flag IN LISTS executable_link_flags)
  cpp_string("${flag}" flag)
  string(APPEND link_flags "${flag}, ")
endforeach()

file(WRITE "${directory}/executable_tools.inc" "#include \"commands/lift.h\"\n\n"
  "forge::ExecutableToolchain forge::cli::executableTools() {\n"
  "    return {${opt}, ${llc}, \"/usr/bin/xcrun\", ${startup}, ${runtime}, ${sdk}, {${link_flags}}};\n"
  "}\n")
