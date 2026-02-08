#pragma once

//
// Compile-time XOR-encoded strings.
//
// XOR-encoded strings are encoded at compile time and decoded in-place at
// runtime on first access.
//
// Memory layout:
//
//   Before decode:
//     [key][len]['H'^key]['e'^key]['l'^key]['l'^key]['o'^key][0^key]
//      ^    ^    ^-- encoded string data (including null)
//      |    +-- length (N-1, excludes null terminator)
//      +-- XOR key (non-zero when encoded)
//
//   After decode:
//     [0x00][len]['H']['e']['l']['l']['o']['\0']
//      ^         ^-- decoded string (pointer returned to caller)
//      +-- key=0 marks string as decoded
//
//
// The `key` being `0x00` indicates the string has been decoded. This avoids
// needing a separate boolean flag which would have x86 PIC issues.
//

#include <type_traits>

namespace sc {
namespace detail {

//
// Key type: `uint8_t` for `char` strings, `uint16_t` for `wchar_t` strings.
//

template <typename CharT>
struct xor_key {
    using type = std::conditional_t<sizeof(CharT) == 1, uint8_t, uint16_t>;
};

//
// Compile-time encoded string. The consteval constructor XORs each
// character with the `key`, so the encoded data is baked into the binary.
//

template <typename CharT, size_t N>
struct xor_string {
    using key_type = typename xor_key<CharT>::type;

    key_type key;
    key_type len;
    CharT data[N];

    consteval xor_string(const CharT (&str)[N], key_type k)
        : key(k), len(static_cast<key_type>(N - 1)), data{} {
        for (size_t i = 0; i < N; i++) {
            data[i] = str[i] ^ static_cast<CharT>(k);
        }
    }
};

//
// Decode a XOR-encoded string in-place. If `key != 0`, XOR each char
// with the `key` and set `key` to `0` (marking it as decoded). Returns a
// pointer to the decoded string data. Safe to call multiple times -
// subsequent calls see `key=0` and skip decoding.
//

template <typename CharT>
__forceinline
CharT* decode_xor(void* ptr) {
    using key_type = typename xor_key<CharT>::type;

    key_type* p = static_cast<key_type*>(ptr);
    key_type key = p[0];
    if (key != 0) {
        key_type len = p[1];
        CharT* str = reinterpret_cast<CharT*>(p + 2);
        for (key_type i = 0; i <= len; i++) {
            str[i] ^= static_cast<CharT>(key);
        }
        p[0] = 0;
    }
    return reinterpret_cast<CharT*>(p + 2);
}

//
// XOR key derivation from `__LINE__`. We use `__LINE__` instead of `__COUNTER__`
// because `__COUNTER__` is already used by `IMPORT_MODULE`/`IMPORT_SYMBOL` to
// generate unique template IDs. Using it here too would cause ID collisions.
//
// The formula scrambles the line number into a non-zero key.
// The `| 1` ensures the key is never zero, since zero means "already decoded".
//

#define SCFW_XOR_KEY(c, CharT)                                                \
    static_cast<typename sc::detail::xor_key<CharT>::type>(                   \
        (sizeof(CharT) == 1)                                                  \
            ? (((c) * 0x9E + 0x5A) | 1)                                       \
            : (((c) * 0x9E37 + 0x5A5A) | 1))

//
// `_TX(s)` - create a static XOR-encoded string and decode it on first use.
// On x86, the address of the static `xor_string` is PIC-adjusted via `_()`.
//

#ifdef _M_IX86
#   define _TX(s) ([]() { \
        using CharT = std::remove_const_t<std::remove_reference_t<decltype(s[0])>>; \
        static sc::detail::xor_string<CharT, sizeof(s)/sizeof(CharT)> _xstr(s, SCFW_XOR_KEY(__LINE__, CharT)); \
        return decode_xor<CharT>(_(&_xstr)); \
    }())
#else
#   define _TX(s) ([]() { \
        using CharT = std::remove_const_t<std::remove_reference_t<decltype(s[0])>>; \
        static sc::detail::xor_string<CharT, sizeof(s)/sizeof(CharT)> _xstr(s, SCFW_XOR_KEY(__LINE__, CharT)); \
        return decode_xor<CharT>(&_xstr); \
    }())
#endif

} // namespace detail
} // namespace sc
