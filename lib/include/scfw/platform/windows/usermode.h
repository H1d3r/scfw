#pragma once

//
// Windows usermode platform backend.
//
// Specializes the dispatch table base class for user-mode shellcode.
// Handles init-time resolution of kernel32 functions (`VirtualFree`,
// `LoadLibraryA`, `FreeLibrary`, `GetProcAddress`) and module lookup via PEB.
//
//=============================================================================
// USERMODE-SPECIFIC OPTIONS
//=============================================================================
//
//   SCFW_ENABLE_FULL_MODULE_SEARCH
//     Disables the ntdll/kernel32 fast-path optimization. By default,
//     find_module("ntdll.dll") and find_module("kernel32.dll") use
//     hardcoded PEB offsets (2nd and 3rd entries). Define this to always
//     walk the full module list instead.
//
//   SCFW_ENABLE_FIND_MODULE_FORWARDER
//     Enables support for forwarded PE exports. Some exports redirect
//     to another DLL (e.g., kernel32!HeapAlloc -> ntdll!RtlAllocateHeap).
//     When enabled, lookup_symbol detects these and recursively resolves
//     the target. Adds code size; only enable if you need it.
//
//=============================================================================
// DISPATCH TABLE BASE LAYOUT
//=============================================================================
//
// The base `dispatch_table_impl<0, user_mode>` holds optional function
// pointers resolved during `init()`. The assembly startup code accesses
// these at hardcoded offsets (see MEMORY LAYOUT in `runtime.h`):
//
//   cleanup_       -> _cleanup_usermode (asm function that calls free_)
//   free_          -> VirtualFree
//   load_module_   -> LoadLibraryA
//   unload_module_ -> FreeLibrary
//   lookup_symbol_ -> GetProcAddress
//
// After `_entry` returns, the asm startup code reads `cleanup_` from offset
// 0 and tail-calls it. `cleanup_` then reads `free_` (`VirtualFree`) from
// offset 4/8 and tail-calls that to free the shellcode memory.
//

#include "common.h"
#include "../../runtime.h"

#ifdef SCFW_MODE
#   error "SCFW_MODE already defined!"
#endif

#define SCFW_MODE user_mode

#ifdef SCFW_ENABLE_CLEANUP
extern "C" void __fastcall _cleanup_usermode(void* table_addr, void* return_addr);
#endif

namespace sc {
namespace detail {

struct user_mode;

//
// Usermode type bindings. Maps abstract operations to concrete
// Windows API function signatures.
//

template<>
struct mode_traits<user_mode> {
#ifdef SCFW_ENABLE_CLEANUP
    using cleanup_fn = decltype(&::_cleanup_usermode);
    using free_fn = decltype(&::VirtualFree);
#endif
#ifdef SCFW_ENABLE_LOAD_MODULE
    using load_module_fn = decltype(&::LoadLibraryA);
#endif
#ifdef SCFW_ENABLE_UNLOAD_MODULE
    using unload_module_fn = decltype(&::FreeLibrary);
#endif
#ifdef SCFW_ENABLE_LOOKUP_SYMBOL
    using lookup_symbol_fn = decltype(&::GetProcAddress);
#endif

    static void* find_module(const char* name) {
#ifndef SCFW_ENABLE_FULL_MODULE_SEARCH
        // Constant string comparisons - the compiler optimizes these away at
        // compile time, keeping only the matching branch.
        if (_stricmp(name, "ntdll.dll") == 0) {
            return windows::usermode::find_module_ntdll();
        }

        if (_stricmp(name, "kernel32.dll") == 0) {
            return windows::usermode::find_module_kernel32();
        }
#endif
        return windows::usermode::find_module(name);
    }

    static void* find_module(uint32_t hash) {
#ifndef SCFW_ENABLE_FULL_MODULE_SEARCH
        // Constant string comparisons - the compiler optimizes these away at
        // compile time, keeping only the matching branch.
        if (hash == fnv1a_hash("ntdll.dll")) {
            return windows::usermode::find_module_ntdll();
        }
        if (hash == fnv1a_hash("kernel32.dll")) {
            return windows::usermode::find_module_kernel32();
        }
#endif
        return windows::usermode::find_module(hash);
    }

    template <typename F>
    static F lookup_symbol(void* module, const char* name) {
        return windows::lookup_symbol<F>(module, name);
    }

    template <typename F>
    static F lookup_symbol(void* module, uint32_t hash) {
        return windows::lookup_symbol<F>(module, hash);
    }
};

template<>
__forceinline
int dispatch_table_impl<0, user_mode>::init(void* argument1, void* argument2) {
    (void)argument1;
    (void)argument2;

    //
    // These macros control how module/symbol names are passed to
    // `find_module/lookup_symbol` during the base init. By default,
    // names are hashed with FNV-1a so no plaintext appears in the binary.
    // `SCFW_ENABLE_INIT_MODULES_BY_STRING` / `SCFW_ENABLE_INIT_SYMBOLS_BY_STRING`
    // switch to string comparison instead.
    //

#ifdef SCFW_ENABLE_INIT_MODULES_BY_STRING
#   define SCFW__MODULE(x) _(x)
#else
#   define SCFW__MODULE(x) fnv1a_hash(x)
#endif
#ifdef SCFW_ENABLE_INIT_SYMBOLS_BY_STRING
#   define SCFW__SYMBOL(x) _(x)
#else
#   define SCFW__SYMBOL(x) fnv1a_hash(x)
#endif

#ifdef SCFW_ENABLE_CLEANUP
    this->cleanup_ = reinterpret_cast<typename mode::cleanup_fn>(_(&::_cleanup_usermode));
#endif

    //
    // We need `kernel32` to resolve `VirtualFree`, `GetProcAddress`,
    // `LoadLibraryA`, and/or `FreeLibrary`.
    //
    // Only find it if at least one is enabled.
    //
#if defined(SCFW_ENABLE_CLEANUP)                                              \
    || defined(SCFW_ENABLE_LOOKUP_SYMBOL)                                     \
    || defined(SCFW_ENABLE_LOAD_MODULE)                                       \
    || defined(SCFW_ENABLE_UNLOAD_MODULE)
    auto kernel32 = mode::find_module(SCFW__MODULE("kernel32.dll"));
#endif

    //
    // Resolve the `kernel32` functions we need. Each one is looked up
    // from the PE export table (or via hash) and stored in the dispatch
    // table for use by the assembly startup code or by `IMPORT_MODULE`
    // `init`/`destroy` methods.
    //

#ifdef SCFW_ENABLE_CLEANUP
    this->free_ = mode::lookup_symbol<typename mode::free_fn>(kernel32, SCFW__SYMBOL("VirtualFree"));
#endif
#ifdef SCFW_ENABLE_LOOKUP_SYMBOL
    this->lookup_symbol_ = mode::lookup_symbol<typename mode::lookup_symbol_fn>(kernel32, SCFW__SYMBOL("GetProcAddress"));
#endif
#ifdef SCFW_ENABLE_LOAD_MODULE
    this->load_module_ = mode::lookup_symbol<typename mode::load_module_fn>(kernel32, SCFW__SYMBOL("LoadLibraryA"));
#endif
#ifdef SCFW_ENABLE_UNLOAD_MODULE
    this->unload_module_ = mode::lookup_symbol<typename mode::unload_module_fn>(kernel32, SCFW__SYMBOL("FreeLibrary"));
#endif

#undef SCFW__SYMBOL
#undef SCFW__MODULE

    return 0;
}

template<>
__forceinline
void dispatch_table_impl<0, user_mode>::destroy(void* argument1, void* argument2) {
    //
    // Base destroy is intentionally empty. Cleanup (freeing shellcode
    // memory) is handled by the assembly code after `_entry` returns,
    // not here. Module-level destroy handles `FreeLibrary` if needed.
    //

    (void)argument1;
    (void)argument2;
}

#ifdef SCFW_ENABLE_LOAD_MODULE
template<>
__forceinline
void* dispatch_table_impl<0, user_mode>::load_module(const char* name) {
    return this->load_module_(name);
}
#endif

#ifdef SCFW_ENABLE_UNLOAD_MODULE
template<>
__forceinline
void dispatch_table_impl<0, user_mode>::unload_module(void* module) {
    this->unload_module_(static_cast<HMODULE>(module));
}
#endif

template<>
__forceinline
void* dispatch_table_impl<0, user_mode>::find_module(const char* name) const {
    return mode::find_module(name);
}

template<>
__forceinline
void* dispatch_table_impl<0, user_mode>::find_module(uint32_t hash) const {
    return mode::find_module(hash);
}

//
// When `SCFW_ENABLE_LOOKUP_SYMBOL` is active, symbol lookup goes through
// `GetProcAddress` (stored in `lookup_symbol_`) instead of manual PE parsing.
// Used when `SCFW_FLAG_DYNAMIC_RESOLVE` is set.
//

#ifdef SCFW_ENABLE_LOOKUP_SYMBOL
template<>
template <typename F>
__forceinline
F dispatch_table_impl<0, user_mode>::lookup_symbol(void* module, const char* name) const {
    return reinterpret_cast<F>(this->lookup_symbol_(static_cast<HMODULE>(module), name));
}
#endif

} // namespace detail
} // namespace sc
