; This native caller knows only ABI v1. Its pointers address host-owned ABI objects.
target triple = "arm64-apple-macosx11.0.0"

@RuntimeIrExpectedAbi = constant i32 1

declare i32 @forge_rt_set_last_error(ptr, i64, i32)
declare i32 @forge_rt_get_last_error(ptr, i64, ptr)

define i32 @runtimeIrRoundtrip(ptr %instance, i64 %thread, i32 %expected) {
entry:
  %out = alloca i32, align 4
  store i32 0, ptr %out, align 4
  %set = call i32 @forge_rt_set_last_error(ptr %instance, i64 %thread, i32 %expected)
  %written = icmp eq i32 %set, 0
  br i1 %written, label %read, label %failed

read:
  %get = call i32 @forge_rt_get_last_error(ptr %instance, i64 %thread, ptr %out)
  %success = icmp eq i32 %get, 0
  %value = load i32, ptr %out, align 4
  %equal = icmp eq i32 %value, %expected
  %passed = and i1 %success, %equal
  %result = select i1 %passed, i32 0, i32 1
  ret i32 %result

failed:
  ret i32 1
}
