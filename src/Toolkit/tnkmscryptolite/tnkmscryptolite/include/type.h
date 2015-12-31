#ifndef __TYPE_H__
#define __TYPE_H__

#ifdef __cplusplus
extern "C"
{
#endif

/*
#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
#define SHA_LONG64 unsigned __int64
#define U64(C)     C##UI64
#elif defined(__arch64__)
#define SHA_LONG64 unsigned long
#define U64(C)     C##UL
#else
#define SHA_LONG64 unsigned long long
#define U64(C)     C##ULL
#endif
*/
#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
#define U64 unsigned __int64
#elif defined(__arch64__)
#define U64 unsigned long
#else
#define U64 unsigned long long
#endif

#define U32 unsigned int
#define U16 unsigned short
#define U8 unsigned char
#define S32 int
#define S16 short
#define S8 char

#undef TRUE
#define TRUE	1
#undef FALSE
#define FALSE	0

#ifdef __cplusplus
}
#endif

#endif
