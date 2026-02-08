#pragma once

//
// Windows kernel-mode platform backend.
//
// Specializes the dispatch table base class for kernel-mode shellcode.
// Module resolution uses `ZwQuerySystemInformation(SystemModuleInformation)`
// instead of walking the PEB. Symbol resolution reuses the same PE export
// parser as usermode (`lookup_symbol` in `common.h`).
//
// Dynamic module loading and dynamic symbol lookup are not available in
// kernel mode and will trigger a `static_assert` if enabled.
//
// N.B. MmGetSystemRoutineAddress could be used, but since it does not support
//      loading from arbitrary modules, it would not be very useful for our
//      purposes.
//

#include "common.h"
#include "../../runtime.h"

#ifdef SCFW_MODE
#   error "SCFW_MODE already defined!"
#endif

#define SCFW_MODE kernel_mode

#ifdef SCFW_ENABLE_CLEANUP
extern "C" void __fastcall _cleanup_kernelmode(void* table_addr, void* return_addr);
#endif

namespace sc {
namespace detail {

struct kernel_mode;

//
// Kernel-mode type bindings. Maps abstract operations to kernel API
// function signatures. Dynamic load/unload/lookup are not supported.
//

template<>
struct mode_traits<kernel_mode> {
#ifdef SCFW_ENABLE_CLEANUP
    using cleanup_fn = decltype(&::_cleanup_kernelmode);
    using free_fn = decltype(&windows::kernelmode::ExFreePool);
#endif
#ifdef SCFW_ENABLE_LOAD_MODULE
    static_assert(false, "Dynamic module loading is not supported in kernel mode");
    using load_module_fn = void;
#endif
#ifdef SCFW_ENABLE_UNLOAD_MODULE
    static_assert(false, "Dynamic module unloading is not supported in kernel mode");
    using unload_module_fn = void;
#endif
#ifdef SCFW_ENABLE_LOOKUP_SYMBOL
    static_assert(false, "Dynamic symbol lookup is not supported in kernel mode");
    using lookup_symbol_fn = void;
#endif

    void* find_module(const char* name) const {
        if (_stricmp(name, "ntoskrnl.exe") == 0) {
            return kernel_base;
        }
        return windows::kernelmode::find_module(kernel_base, name);
    }

    void* find_module(uint32_t hash) const {
        if (hash == fnv1a_hash("ntoskrnl.exe")) {
            return kernel_base;
        }
        return windows::kernelmode::find_module(kernel_base, hash);
    }

    template <typename F>
    static F lookup_symbol(void* module, const char* name) {
        return windows::lookup_symbol<F>(module, name);
    }

    template <typename F>
    static F lookup_symbol(void* module, uint32_t hash) {
        return windows::lookup_symbol<F>(module, hash);
    }

    void* kernel_base;
};

//
// Kernel-mode init. `argument1` is the ntoskrnl base address,
// used to bootstrap symbol resolution.
//

template<>
__forceinline
int dispatch_table_impl<0, kernel_mode>::init(void* argument1, void* argument2) {
    (void)argument2;
    void* kernel_base = argument1;

#ifdef SCFW_ENABLE_INIT_SYMBOLS_BY_STRING
#   define SCFW__SYMBOL(x) _(x)
#else
#   define SCFW__SYMBOL(x) fnv1a_hash(x)
#endif

#ifdef SCFW_ENABLE_CLEANUP
    this->cleanup_ = reinterpret_cast<typename mode::cleanup_fn>(_(&::_cleanup_kernelmode));
    this->free_ = mode::lookup_symbol<typename mode::free_fn>(kernel_base, SCFW__SYMBOL("ExFreePool"));
#endif

    this->mode_.kernel_base = kernel_base;

    return 0;
}

template<>
__forceinline
void dispatch_table_impl<0, kernel_mode>::destroy(void* argument1, void* argument2) {
    (void)argument1;
    (void)argument2;
}


#ifdef SCFW_ENABLE_LOAD_MODULE
static_assert(false, "Dynamic module loading is not supported in kernel mode");
#endif

#ifdef SCFW_ENABLE_UNLOAD_MODULE
static_assert(false, "Dynamic module unloading is not supported in kernel mode");
#endif

template<>
__forceinline
void* dispatch_table_impl<0, kernel_mode>::find_module(const char* name) const {
    return mode_.find_module(name);
}

template<>
__forceinline
void* dispatch_table_impl<0, kernel_mode>::find_module(uint32_t hash) const {
    return mode_.find_module(hash);
}

#ifdef SCFW_ENABLE_LOOKUP_SYMBOL
static_assert(false, "Dynamic symbol lookup is not supported in kernel mode");
#endif

} // namespace detail
} // namespace sc
