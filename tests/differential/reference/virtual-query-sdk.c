/* Compile with the Windows Server runner's x64 Windows SDK. */
#include <stddef.h>
#include <windows.h>

#define FIELD(name, offset, size)                                                                  \
    _Static_assert(offsetof(MEMORY_BASIC_INFORMATION, name) == offset &&                           \
                       sizeof(((MEMORY_BASIC_INFORMATION *)0)->name) == size,                      \
                   #name)
_Static_assert(sizeof(MEMORY_BASIC_INFORMATION) == 48, "Windows x64 layout");
FIELD(BaseAddress, 0, 8);
FIELD(AllocationBase, 8, 8);
FIELD(AllocationProtect, 16, 4);
FIELD(PartitionId, 20, 2);
FIELD(RegionSize, 24, 8);
FIELD(State, 32, 4);
FIELD(Protect, 36, 4);
FIELD(Type, 40, 4);
