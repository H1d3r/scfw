#include <ntddk.h>

//
// Suppress "nonstandard extension used: nameless struct/union" warnings.
//
#pragma warning (disable : 4201)

#define MEMORY_TAG '  cS'

typedef (__fastcall* PSHELLCODE_ROUTINE)(PVOID Argument1, PVOID Argument2);
UCHAR ShellcodeData[] = {
    // Paste your shellcode bytes here.
    0x90, 0x90, 0xC3
};

NTSYSAPI
PVOID
NTAPI
RtlPcToFileHeader (
    _In_ PVOID PcValue,
    _Out_ PVOID* BaseOfImage
    );

NTSTATUS
NTAPI
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    //
    // Get the ntoskrnl.exe ImageBase.
    //

    PVOID KernelBase = NULL;
    RtlPcToFileHeader((PVOID)&RtlPcToFileHeader, &KernelBase);

    if (!KernelBase)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "[!] Cannot determine ntoskrnl.exe ImageBase!\n");
        return STATUS_NOT_FOUND;
    }

    //
    // Allocate memory for the shellcode.
    //

    PVOID Shellcode = ExAllocatePoolWithTag(NonPagedPool,
                                            sizeof(ShellcodeData),
                                            MEMORY_TAG);
    if (!Shellcode)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "[!] Cannot allocate memory for the shellcode!\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(Shellcode, ShellcodeData, sizeof(ShellcodeData));

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_ERROR_LEVEL,
               "[ ] Loaded %lu bytes at 0x%p\n",
               sizeof(ShellcodeData),
               Shellcode);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_ERROR_LEVEL,
               "[ ] Executing shellcode\n\n");

    //
    // Run it!
    //

    ((PSHELLCODE_ROUTINE)Shellcode)(KernelBase, PsGetCurrentProcess());

    //
    // Check if the shellcode cleaned up after itself.
    //
    // N.B. This is obviously dangerous. If it did clean up after itself,
    //      the memory might not be mapped at all.
    //


    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_ERROR_LEVEL,
               "\n[ ] Shellcode returned\n");

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_ERROR_LEVEL,
               "-------------------------------------------------------------\n");

    return STATUS_UNSUCCESSFUL;
}
