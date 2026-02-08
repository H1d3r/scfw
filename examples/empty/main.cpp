#include <scfw/runtime.h>
#include <scfw/platform/windows/usermode.h>

IMPORT_BEGIN();

IMPORT_END();

namespace sc {

extern "C" void __fastcall entry(void* argument1, void* argument2)
{
    (void)argument1;
    (void)argument2;
}

} // namespace sc
