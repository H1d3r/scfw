#define SCFW_ENABLE_LOAD_MODULE

#include <scfw/runtime.h>
#include <scfw/platform/windows/usermode.h>

IMPORT_BEGIN();
    IMPORT_MODULE("user32.dll", FLAGS(SCFW_FLAG_DYNAMIC_LOAD));
        IMPORT_SYMBOL(MessageBoxA);
IMPORT_END();

namespace sc {

extern "C" void __fastcall entry(void* argument1, void* argument2)
{
    (void)argument1;
    (void)argument2;

    MessageBoxA(NULL, _T("Hello, World!"), _T("shellcode"), MB_OK);
}

} // namespace sc
