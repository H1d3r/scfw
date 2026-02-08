    .intel_syntax noprefix

#ifndef SCFW_P2ALIGN
#   define SCFW_P2ALIGN 4
#endif

#
# Externally used symbols.
#

#ifdef SCFW_ENABLE_CLEANUP
    .extern _start
#else
    .extern _entry
#endif

#
# .text$00 is the very first section in the final binary.
# _init is the PE entry point (/ENTRY:_init), so it must be
# placed here to be the first instruction executed.
#

    .section .text$00,"ax"

#++
#
# void
# _init (
#    _In_ void* argument1,
#    _In_ void* argument2
#    )
#
# Routine Description:
#
#    PE entry point. Captures the shellcode's base address (its own
#    location in memory) and jumps to _start (with cleanup) or
#    directly to _entry (without cleanup).
#
# Arguments:
#
#    argument1 - Value of RCX register.
#    argument2 - Value of RDX register.
#
# Return Value:
#
#    None.
#
#--

    .globl _init
    .p2align SCFW_P2ALIGN
_init:

#ifdef SCFW_ENABLE_CLEANUP
#
# Save the shellcode base address in r11 (scratch register, callee-clobbered).
# _start will preserve it across the _entry call and pass it to _cleanup_*
# so VirtualFree knows what memory to free.
#

    lea     r11, [rip + _init]
    jmp     _start
#else
    jmp     _entry
#endif

    .p2align SCFW_P2ALIGN
