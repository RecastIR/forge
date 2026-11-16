; This native caller knows only ABI v1. Its pointers address host-owned ABI objects.
target triple = "arm64-apple-macosx11.0.0"

@RuntimeIrExpectedAbi = constant i32 1

declare i32 @forge_rt_set_last_error(ptr, i64, i32)
declare i32 @forge_rt_get_last_error(ptr, i64, ptr)

; Load each token from memory so an incoming register cannot supply its high bits by accident.
define i32 @runtimeIrSetLastError(ptr %instance, ptr %token, i32 %value) {
entry:
  %thread = load i64, ptr %token, align 8
  %status = call i32 @forge_rt_set_last_error(ptr %instance, i64 %thread, i32 %value)
  ret i32 %status
}

define i32 @runtimeIrGetLastError(ptr %instance, ptr %token, ptr %out) {
entry:
  %thread = load i64, ptr %token, align 8
  %status = call i32 @forge_rt_get_last_error(ptr %instance, i64 %thread, ptr %out)
  ret i32 %status
}
