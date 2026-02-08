#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int
main(
    int argc,
    char** argv
    )
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: scrun <input.bin> [arg1] [arg2]\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Loads and executes a shellcode binary.\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Arguments:\n");
        fprintf(stderr, "  input.bin  Path to the shellcode binary file\n");
        fprintf(stderr, "  arg1       Optional first argument (passed in RCX/ECX)\n");
        fprintf(stderr, "  arg2       Optional second argument (passed in RDX/EDX)\n");
        return 1;
    }

    //
    // Open the shellcode file.
    //

    HANDLE FileHandle = CreateFileA(argv[1],
                                    GENERIC_READ,
                                    FILE_SHARE_READ,
                                    NULL,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    NULL);

    if (FileHandle == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "[!] Error: Failed to open file '%s' (error %lu)\n",
                argv[1], GetLastError());
        return 1;
    }

    //
    // Get file size.
    //

    DWORD FileSize = GetFileSize(FileHandle, NULL);

    if (FileSize == INVALID_FILE_SIZE)
    {
        fprintf(stderr, "[!] Error: Failed to get file size (error %lu)\n",
                GetLastError());
        CloseHandle(FileHandle);
        return 1;
    }

    if (FileSize == 0)
    {
        fprintf(stderr, "[!] Error: File is empty\n");
        CloseHandle(FileHandle);
        return 1;
    }

    //
    // Allocate executable memory.
    //

    LPVOID BaseAddress = VirtualAlloc(NULL,
                                      FileSize,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);

    if (BaseAddress == NULL)
    {
        fprintf(stderr, "[!] Error: Failed to allocate memory (error %lu)\n",
                GetLastError());
        CloseHandle(FileHandle);
        return 1;
    }

    //
    // Read shellcode into memory.
    //

    DWORD BytesRead = 0;
    BOOL Success = ReadFile(FileHandle,
                            BaseAddress,
                            FileSize,
                            &BytesRead,
                            NULL);

    CloseHandle(FileHandle);

    if (!Success || BytesRead != FileSize)
    {
        fprintf(stderr, "[!] Error: Failed to read file (error %lu)\n",
                GetLastError());
        VirtualFree(BaseAddress, 0, MEM_RELEASE);
        return 1;
    }

    printf("[ ] Loaded %lu bytes at 0x%p\n", FileSize, BaseAddress);
    printf("[ ] Executing shellcode\n\n");

    //
    // Parse optional arguments.
    //

    PVOID Arg1 = (argc > 2) ? (PVOID)(ULONG_PTR)strtoull(argv[2], NULL, 0) : NULL;
    PVOID Arg2 = (argc > 3) ? (PVOID)(ULONG_PTR)strtoull(argv[3], NULL, 0) : NULL;

    //
    // Execute the shellcode.
    //
    // The shellcode entry point signature is:
    //   void __fastcall entry(void* argument1, void* argument2)
    //

    typedef void (__fastcall* ShellcodeEntry)(PVOID, PVOID);
    ShellcodeEntry Shellcode = (ShellcodeEntry)BaseAddress;

    Shellcode(Arg1, Arg2);

    printf("\n[ ] Shellcode returned\n");

    //
    // Test if the shellcode freed itself. If not, free the memory here.
    //

    DWORD OldProtect = 0;
    if (VirtualProtect(BaseAddress, FileSize, PAGE_NOACCESS, &OldProtect))
    {
        printf("[*] Memory freed: NO\n");
        VirtualFree(BaseAddress, 0, MEM_RELEASE);
    }
    else
    {
        printf("[ ] Memory freed: YES\n");
    }

    return 0;
}
