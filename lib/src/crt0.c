//
// ???
//

#pragma code_seg(".text$50")

#include <stddef.h>

void* __cdecl memset(void* dest, int ch, size_t count)
{
    unsigned char* p = (unsigned char*)dest;
    while (count--)
        *p++ = (unsigned char)ch;
    return dest;
}
