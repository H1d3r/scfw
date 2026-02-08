#pragma once

//
// Position-independent code (PIC) helpers.
//
// On x86, the compiler generates absolute addresses for globals and
// string literals. When shellcode is loaded at an arbitrary address,
// those addresses are wrong. `_pic()` fixes them at runtime.
//
// On x64, RIP-relative addressing handles this automatically, so
// `_pic()` is not needed and `_()` is a no-op.
//

#include <cstdint>
#include <type_traits>
#include "xorstr.h"

//
// Returns the runtime address of the `_pc` function itself.
// Implemented in assembly (x86: `call/pop` trick, x64: `lea rip`).
//
extern "C" __attribute__((const)) void* _pc();

//
// On x86, the compiler generates absolute addresses for global variables.
// When shellcode is copied to a new location, these addresses point to the
// wrong memory.
//
// Calculate the runtime address using the difference between where we ARE
// and where we were COMPILED to be.
//
//-----------------------------------------------------------------------------
// How _pic() Works
//-----------------------------------------------------------------------------
//
//   Compile-time layout:          Runtime layout:
//   +------------------+          +------------------+
//   | 0x00401000: _pc  |          | 0x7FFE0000: _pc  |  <-- _pc() returns
//   | ...              |          | ...              |      this address.
//   | 0x00402000: data |          | 0x7FFE1000: data |
//   +------------------+          +------------------+
//
//   Formula: runtime_addr = _pc() - &_pc + compile_time_addr
//
//   Example:
//     _pc() = 0x7FFE0000 (actual runtime address of _pc function).
//     &_pc  = 0x00401000 (compile-time address, embedded in instruction).
//     addr  = 0x00402000 (compile-time address of data).
//
//     result = 0x7FFE0000 - 0x00401000 + 0x00402000
//            = 0x7FFE1000 (correct runtime address of data).
//
// The DIFFERENCE between any two compile-time addresses equals the difference
// between their runtime addresses. The `/fixed` linker flag ensures no `.reloc`
// section is generated, so compile-time addresses are preserved as constants
// in the binary.
//

template <typename T>
__forceinline
T* _pic(T* addr)
{
    return reinterpret_cast<T*>(
      reinterpret_cast<uintptr_t>(_pc()) -
      reinterpret_cast<uintptr_t>(&_pc) +
      reinterpret_cast<uintptr_t>(addr));
}

#ifdef _M_IX86
#   define _(x) _pic(x)
#else
#   define _(x) (x)
#endif

//
// _T(s) - get a runtime-safe pointer to string literal `s`.
//
// Depending on configuration, this either:
//   - just returns the string pointer as-is (x64 without XOR),
//   - returns a PIC-relocated pointer to a static copy (x86 without XOR),
//   - XOR-encodes at compile time and decodes on first use
//     (when `SCFW_ENABLE_XOR_STRING` is defined).
//
// Use `_T()` for any string that ends up in the binary (module names,
// symbol names, user strings). Handles both `char` and `wchar_t`.
//

#ifdef SCFW_ENABLE_XOR_STRING
#   define _T(s) _TX(s)
#else
#   ifdef _M_IX86
#       define _T(s) ([]() { \
            using CharT = std::remove_const_t<std::remove_reference_t<decltype(s[0])>>; \
            static CharT _str[] = s; \
            return _(static_cast<CharT*>(_str)); \
        }())
#   else
#       define _T(s) ([]() { \
            using CharT = std::remove_const_t<std::remove_reference_t<decltype(s[0])>>; \
            return const_cast<CharT*>(s); \
        }())
#   endif
#endif
