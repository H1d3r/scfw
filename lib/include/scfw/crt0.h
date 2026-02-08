#pragma once

//
// Minimal C runtime. Inline implementations of standard C string and
// memory functions. We can't link against the real CRT (no stdlib),
// so these are provided as __forceinline to be inlined at every call
// site with zero overhead.
//
// Also includes _wcsicmpa() for comparing wchar_t* against char*,
// used when searching PEB module names (wide) by ASCII name.
//

#include <cstdint>

extern "C" {

__forceinline
int __cdecl memcmp(const void* lhs, const void* rhs, size_t count)
{
    const unsigned char* p1 = (const unsigned char*)lhs;
    const unsigned char* p2 = (const unsigned char*)rhs;
    while (count--)
    {
        if (*p1 != *p2)
            return *p1 - *p2;
        p1++;
        p2++;
    }
    return 0;
}

__forceinline
void* __cdecl memset(void* dest, int ch, size_t count)
{
    unsigned char* p = (unsigned char*)dest;
    while (count--)
        *p++ = (unsigned char)ch;
    return dest;
}

__forceinline
void* __cdecl memcpy(void* dest, const void* src, size_t count)
{
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    while (count--)
        *d++ = *s++;
    return dest;
}

__forceinline
void* __cdecl memmove(void* dest, const void* src, size_t count)
{
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    if (d < s)
    {
        while (count--)
            *d++ = *s++;
    }
    else
    {
        d += count;
        s += count;
        while (count--)
            *--d = *--s;
    }
    return dest;
}

__forceinline
const void* __cdecl memchr(const void* ptr, int ch, size_t count)
{
    const unsigned char* p = (const unsigned char*)ptr;
    while (count--)
    {
        if (*p == (unsigned char)ch)
            return (const void*)p;
        p++;
    }
    return 0;
}

__forceinline
size_t __cdecl strlen(const char* str)
{
    const char* p = str;
    while (*p)
        p++;
    return (size_t)(p - str);
}

__forceinline
size_t __cdecl wcslen(const wchar_t* str)
{
    const wchar_t* p = str;
    while (*p)
        p++;
    return (size_t)(p - str);
}

__forceinline
char* __cdecl strcpy(char* dest, const char* src)
{
    char* d = dest;
    while ((*d++ = *src++))
        ;
    return dest;
}

__forceinline
wchar_t* __cdecl wcscpy(wchar_t* dest, const wchar_t* src)
{
    wchar_t* d = dest;
    while ((*d++ = *src++))
        ;
    return dest;
}

__forceinline
char* __cdecl strncpy(char* dest, const char* src, size_t count)
{
    char* d = dest;
    while (count && (*d++ = *src++))
        count--;
    while (count--)
        *d++ = '\0';
    return dest;
}

__forceinline
int __cdecl strcmp(const char* lhs, const char* rhs)
{
    while (*lhs && (*lhs == *rhs))
    {
        lhs++;
        rhs++;
    }
    return *(unsigned char*)lhs - *(unsigned char*)rhs;
}

__forceinline
int __cdecl strncmp(const char* lhs, const char* rhs, size_t count)
{
    while (count && *lhs && (*lhs == *rhs))
    {
        lhs++;
        rhs++;
        count--;
    }
    return count ? (*(unsigned char*)lhs - *(unsigned char*)rhs) : 0;
}

__forceinline
int __cdecl _stricmp(const char* lhs, const char* rhs)
{
    char c1, c2;

    do
    {
        c1 = *lhs++;
        c2 = *rhs++;

        if (c1 >= 'A' && c1 <= 'Z')
            c1 += ('a' - 'A');
        if (c2 >= 'A' && c2 <= 'Z')
            c2 += ('a' - 'A');
    } while (c1 && (c1 == c2));

    return (int)((unsigned char)c1 - (unsigned char)c2);
}


__forceinline
int __cdecl _wcsicmp(const wchar_t* lhs, const wchar_t* rhs)
{
    wchar_t c1, c2;

    do
    {
        c1 = *lhs++;
        c2 = *rhs++;

        // Convert to lowercase (ASCII only)
        if (c1 >= L'A' && c1 <= L'Z')
            c1 += (L'a' - L'A');
        if (c2 >= L'A' && c2 <= L'Z')
            c2 += (L'a' - L'A');
    } while (c1 && (c1 == c2));

    return (int)(c1 - c2);
}

//
// constexpr variant of _stricmp. Can be evaluated at compile time.
//
__forceinline
constexpr int __cdecl _Xstricmp(const char* lhs, const char* rhs)
{
    char c1, c2;

    do
    {
        c1 = *lhs++;
        c2 = *rhs++;

        // Convert to lowercase (ASCII only)
        if (c1 >= 'A' && c1 <= 'Z')
            c1 += ('a' - 'A');
        if (c2 >= 'A' && c2 <= 'Z')
            c2 += ('a' - 'A');
    } while (c1 && (c1 == c2));

    return (int)((unsigned char)c1 - (unsigned char)c2);
}

__forceinline
int __cdecl _wcsicmpa(const wchar_t* lhs, const char* rhs)
{
    wchar_t c1;
    char c2;

    do
    {
        c1 = *lhs++;
        c2 = *rhs++;

        if (c1 >= L'A' && c1 <= L'Z')
            c1 += (L'a' - L'A');
        if (c2 >= 'A' && c2 <= 'Z')
            c2 += ('a' - 'A');
    } while (c1 && (c1 == (wchar_t)c2));

    return (int)(c1 - (wchar_t)c2);
}

__forceinline
char* __cdecl strcat(char* dest, const char* src)
{
    char* d = dest;
    while (*d)
        d++;
    while ((*d++ = *src++))
        ;
    return dest;
}

__forceinline
char* __cdecl strncat(char* dest, const char* src, size_t count)
{
    char* d = dest;
    while (*d)
        d++;
    while (count-- && (*d++ = *src++))
        ;
    if (count == (size_t)-1)
        *d = '\0';
    return dest;
}

__forceinline
const char* __cdecl strchr(const char* str, int ch)
{
    while (*str)
    {
        if (*str == (char)ch)
            return (const char*)str;
        str++;
    }
    return (ch == '\0') ? (const char*)str : 0;
}

__forceinline
const wchar_t* __cdecl wcschr(const wchar_t* str, wchar_t ch)
{
    while (*str)
    {
        if (*str == ch)
            return (const wchar_t*)str;
        str++;
    }
    return (ch == L'\0') ? (const wchar_t*)str : 0;
}

__forceinline
const char* __cdecl strrchr(const char* str, int ch)
{
    const char* last = 0;
    while (*str)
    {
        if (*str == (char)ch)
            last = str;
        str++;
    }
    return (ch == '\0') ? (const char*)str : (const char*)last;
}

__forceinline
const char* __cdecl strstr(const char* str, const char* substr)
{
    if (!*substr)
        return (const char*)str;
    while (*str)
    {
        const char* h = str;
        const char* n = substr;
        while (*h && *n && (*h == *n))
        {
            h++;
            n++;
        }
        if (!*n)
            return (const char*)str;
        str++;
    }
    return 0;
}

}
