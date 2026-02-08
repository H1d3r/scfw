#include <scfw/runtime.h>
#include <scfw/platform/windows/usermode.h>

IMPORT_BEGIN();
    IMPORT_MODULE("kernel32.dll");
        IMPORT_SYMBOL(WriteConsoleA);
IMPORT_END();

namespace sc {

extern "C" void __fastcall entry(void* argument1, void* argument2)
{
    (void)argument1;
    (void)argument2;

    HANDLE StdOut = NtCurrentPeb()->ProcessParameters->StandardOutput;
    WriteConsoleA(StdOut,
                  _T("Hello, World!\n"),
                  sizeof("Hello, World!\n") - 1,
                  NULL,
                  NULL);
}

} // namespace sc
