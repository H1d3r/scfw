#pragma once

//
// FNV-1a hash function for case-insensitive string hashing.
//
// Used to hash module and symbol names so we don't need to store
// plaintext strings in the shellcode binary. At init time, we hash
// the export names from the PE and compare against the compile-time
// hash to find our target function.
//
// The hash is case-insensitive: bytes >= 'a' get 0x20 subtracted
// (effectively uppercasing ASCII letters). We intentionally skip the
// `<= 'z'` check - it saves a cmp+branch at every inlined call site,
// and since this function is inlined into every module/symbol lookup
// loop, those bytes add up. Mangling characters above 'z' doesn't
// matter because both sides of the comparison use the same hash.
// Handles both `char` and `wchar_t` (only the low byte is hashed,
// which is fine for ASCII names).
//

#include <string>
#include <cstdint>

namespace sc {
namespace detail {

template <typename CharT>
constexpr uint32_t fnv1a_hash(const CharT* string, size_t length) {
    uint32_t hash = 0x811c9dc5;
    uint8_t byte = 0;

    while (length--) {
        byte = static_cast<uint8_t>(*string++);

        if (byte >= 'a') {
            byte -= 0x20;
        }

        hash ^= byte;
        hash *= 0x01000193;
    }

    return hash;
}

template <typename CharT>
constexpr uint32_t fnv1a_hash(const CharT* string) {
    return fnv1a_hash(string, std::char_traits<CharT>::length(string));
}

} // namespace detail
} // namespace sc
