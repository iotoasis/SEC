#ifndef __TYPECONVERT_H__
#define __TYPECONVERT_H__

#include "type.h"

typedef unsigned int seed_word;

#ifdef __cplusplus
extern "C"
{
#endif

#undef U8ToU32
#define U8ToU32(i, o)	(o =((U32)(*((i)++))), \
	 o |= ((U32)(*((i)++))) << 8L, \
	 o |= ((U32)(*((i)++))) << 16L, \
	 o |= ((U32)(*((i)++))) << 24L)

#undef U8ToU32r
#define U8ToU32r(i, o)	(o =((U32)(*((i)++))) << 24L, \
	 o |= ((U32)(*((i)++))) << 16L, \
	 o |= ((U32)(*((i)++))) << 8L, \
	 o |= ((U32)(*((i)++))))

#undef U8ToU32n
#define U8ToU32n(i, o1, o2, n)	{ \
	i += n; \
	o1 = o2 = 0; \
	switch (n) { \
		case 8: o2  = ((U32)(*(--(i)))) << 24L; \
		case 7: o2 |= ((U32)(*(--(i)))) << 16L; \
		case 6: o2 |= ((U32)(*(--(i)))) <<  8L; \
		case 5: o2 |= ((U32)(*(--(i))));		\
		case 4: o1  = ((U32)(*(--(i)))) << 24L; \
		case 3: o1 |= ((U32)(*(--(i)))) << 16L; \
		case 2: o1 |= ((U32)(*(--(i)))) <<  8L; \
		case 1: o1 |= ((U32)(*(--(i))));		\
	} \
}

#undef U8ToU32nr
#define U8ToU32nr(i, o1, o2, n)	{ \
	i += n; \
	o1 = o2 = 0; \
	switch (n) { \
		case 8: o2  = ((U32)(*(--(i))));		\
		case 7: o2 |= ((U32)(*(--(i)))) <<  8L; \
		case 6: o2 |= ((U32)(*(--(i)))) << 16L; \
		case 5: o2 |= ((U32)(*(--(i)))) << 24L; \
		case 4: o1  = ((U32)(*(--(i))));		\
		case 3: o1 |= ((U32)(*(--(i)))) <<  8L; \
		case 2: o1 |= ((U32)(*(--(i)))) << 16L; \
		case 1: o1 |= ((U32)(*(--(i)))) << 24L; \
	} \
}

#undef U8ToU32n2
#define U8ToU32n2(i, o1, o2, o3, o4, n)	{ \
	i += n; \
	o1 = o2 = o3 = o4 = 0; \
	switch (n) { \
		case 16: o4  = ((U32)(*(--(i)))) << 24L; \
		case 15: o4 |= ((U32)(*(--(i)))) << 16L; \
		case 14: o4 |= ((U32)(*(--(i)))) <<  8L; \
		case 13: o4 |= ((U32)(*(--(i))));		 \
		case 12: o3  = ((U32)(*(--(i)))) << 24L; \
		case 11: o3 |= ((U32)(*(--(i)))) << 16L; \
		case 10: o3 |= ((U32)(*(--(i)))) <<  8L; \
		case 9:  o3 |= ((U32)(*(--(i))));		 \
		case 8:  o2  = ((U32)(*(--(i)))) << 24L; \
		case 7:  o2 |= ((U32)(*(--(i)))) << 16L; \
		case 6:  o2 |= ((U32)(*(--(i)))) <<  8L; \
		case 5:  o2 |= ((U32)(*(--(i))));		 \
		case 4:  o1  = ((U32)(*(--(i)))) << 24L; \
		case 3:  o1 |= ((U32)(*(--(i)))) << 16L; \
		case 2:  o1 |= ((U32)(*(--(i)))) <<  8L; \
		case 1:  o1 |= ((U32)(*(--(i))));		 \
	} \
}

#undef U32ToU8
#define U32ToU8(i, o)	(*((o)++)=(U8)(((i)) & 0xff), \
	*((o)++) = (U8)(((i)>> 8L) & 0xff), \
	*((o)++) = (U8)(((i)>>16L) & 0xff), \
	*((o)++) = (U8)(((i)>>24L) & 0xff))

#undef U32ToU8r
#define U32ToU8r(i, o)	(*((o)++)=(U8)(((i)>>24L) & 0xff), \
	*((o)++) = (U8)(((i)>>16L) & 0xff), \
	*((o)++) = (U8)(((i)>> 8L) & 0xff), \
	*((o)++) = (U8)(((i)     ) & 0xff))

#undef U32ToU8n
#define U32ToU8n(i1, i2, o, n)	{ \
	o += n; \
	switch(n) { \
		case 8: *(--(o)) = (U8)(((i2) >> 24L) & 0xff); \
		case 7: *(--(o)) = (U8)(((i2) >> 16L) & 0xff); \
		case 6: *(--(o)) = (U8)(((i2) >>  8L) & 0xff); \
		case 5: *(--(o)) = (U8)(((i2)       ) & 0xff); \
		case 4: *(--(o)) = (U8)(((i1) >> 24L) & 0xff); \
		case 3: *(--(o)) = (U8)(((i1) >> 16L) & 0xff); \
		case 2: *(--(o)) = (U8)(((i1) >>  8L) & 0xff); \
		case 1: *(--(o)) = (U8)(((i1)       ) & 0xff); \
	} \
}

#undef U32ToU8nr
#define U32ToU8nr(i1, i2, o, n)	{ \
	o += n; \
	switch(n) { \
		case 8: *(--(o)) = (U8)(((i2)       ) & 0xff); \
		case 7: *(--(o)) = (U8)(((i2) >>  8L) & 0xff); \
		case 6: *(--(o)) = (U8)(((i2) >> 16L) & 0xff); \
		case 5: *(--(o)) = (U8)(((i2) >> 24L) & 0xff); \
		case 4: *(--(o)) = (U8)(((i1)       ) & 0xff); \
		case 3: *(--(o)) = (U8)(((i1) >>  8L) & 0xff); \
		case 2: *(--(o)) = (U8)(((i1) >> 16L) & 0xff); \
		case 1: *(--(o)) = (U8)(((i1) >> 24L) & 0xff); \
	} \
}

#undef U32ToU8n2
#define U32ToU8n2(i1, i2, i3, i4, o, n)	{ \
	o += n; \
	switch(n) { \
		case 16: *(--(o)) = (U8)(((i4) >> 24L) & 0xff); \
		case 15: *(--(o)) = (U8)(((i4) >> 16L) & 0xff); \
		case 14: *(--(o)) = (U8)(((i4) >>  8L) & 0xff); \
		case 13: *(--(o)) = (U8)(((i4)       ) & 0xff); \
		case 12: *(--(o)) = (U8)(((i3) >> 24L) & 0xff); \
		case 11: *(--(o)) = (U8)(((i3) >> 16L) & 0xff); \
		case 10: *(--(o)) = (U8)(((i3) >>  8L) & 0xff); \
		case 9:  *(--(o)) = (U8)(((i3)       ) & 0xff); \
		case 8:  *(--(o)) = (U8)(((i2) >> 24L) & 0xff); \
		case 7:  *(--(o)) = (U8)(((i2) >> 16L) & 0xff); \
		case 6:  *(--(o)) = (U8)(((i2) >>  8L) & 0xff); \
		case 5:  *(--(o)) = (U8)(((i2)       ) & 0xff); \
		case 4:  *(--(o)) = (U8)(((i1) >> 24L) & 0xff); \
		case 3:  *(--(o)) = (U8)(((i1) >> 16L) & 0xff); \
		case 2:  *(--(o)) = (U8)(((i1) >>  8L) & 0xff); \
		case 1:  *(--(o)) = (U8)(((i1)       ) & 0xff); \
	} \
}

#undef n2s
#define n2s(i, o) (o =((U32)(*((i)++)))<< 8L, \
			 o |= ((U32)(*((i)++)))      )

#define G_FUNC(v)       \
        SS[0][(unsigned char)      (v) & 0xff] ^ SS[1][(unsigned char) ((v)>>8) & 0xff] ^ \
        SS[2][(unsigned char)((v)>>16) & 0xff] ^ SS[3][(unsigned char)((v)>>24) & 0xff]

#define char2word(c, i)  \
        (i) = ((((seed_word)(c)[0]) << 24) | (((seed_word)(c)[1]) << 16) | (((seed_word)(c)[2]) << 8) | ((seed_word)(c)[3]))

#define word2char(l, c)  \
        *((c)+0) = (unsigned char)((l)>>24) & 0xff; \
        *((c)+1) = (unsigned char)((l)>>16) & 0xff; \
        *((c)+2) = (unsigned char)((l)>> 8) & 0xff; \
        *((c)+3) = (unsigned char)((l))     & 0xff

#define KEYSCHEDULE_UPDATE0(T0, T1, X1, X2, X3, X4, KC)  \
        (T0) = (X3);                                     \
        (X3) = (((X3)<<8) ^ ((X4)>>24)) & 0xffffffff;    \
        (X4) = (((X4)<<8) ^ ((T0)>>24)) & 0xffffffff;    \
        (T0) = ((X1) + (X3) - (KC))     & 0xffffffff;    \
        (T1) = ((X2) + (KC) - (X4))     & 0xffffffff

#define KEYSCHEDULE_UPDATE1(T0, T1, X1, X2, X3, X4, KC)  \
        (T0) = (X1);                                     \
        (X1) = (((X1)>>8) ^ ((X2)<<24)) & 0xffffffff;    \
        (X2) = (((X2)>>8) ^ ((T0)<<24)) & 0xffffffff;    \
        (T0) = ((X1) + (X3) - (KC))     & 0xffffffff;     \
        (T1) = ((X2) + (KC) - (X4))     & 0xffffffff

#define KEYUPDATE_TEMP(T0, T1, K)   \
        (K)[0] = G_FUNC((T0));      \
        (K)[1] = G_FUNC((T1))

#define XOR_SEEDBLOCK(DST, SRC)      \
        ((DST))[0] ^= ((SRC))[0];    \
        ((DST))[1] ^= ((SRC))[1];    \
        ((DST))[2] ^= ((SRC))[2];    \
        ((DST))[3] ^= ((SRC))[3]

#define MOV_SEEDBLOCK(DST, SRC)      \
        ((DST))[0] = ((SRC))[0];     \
        ((DST))[1] = ((SRC))[1];     \
        ((DST))[2] = ((SRC))[2];     \
        ((DST))[3] = ((SRC))[3]

# define CHAR2WORD(C, I)              \
        char2word((C),    (I)[0]);    \
        char2word((C+4),  (I)[1]);    \
        char2word((C+8),  (I)[2]);    \
        char2word((C+12), (I)[3])

# define WORD2CHAR(I, C)              \
        word2char((I)[0], (C));       \
        word2char((I)[1], (C+4));     \
        word2char((I)[2], (C+8));     \
        word2char((I)[3], (C+12))

# define E_SEED(T0, T1, X1, X2, X3, X4, rbase)   \
        (T0) = (X3) ^ (ks->data)[(rbase)];       \
        (T1) = (X4) ^ (ks->data)[(rbase)+1];     \
        (T1) ^= (T0);                            \
        (T1) = G_FUNC((T1));                     \
        (T0) = ((T0) + (T1)) & 0xffffffff;       \
        (T0) = G_FUNC((T0));                     \
        (T1) = ((T1) + (T0)) & 0xffffffff;       \
        (T1) = G_FUNC((T1));                     \
        (T0) = ((T0) + (T1)) & 0xffffffff;       \
        (X1) ^= (T0);                            \
        (X2) ^= (T1)

#if defined(_M_X64) || defined(__x86_64__)
#define XOR8x16(r, a, b)																		\
	*((unsigned long long *)(r)      ) = *((unsigned long long *)(a)      ) ^ *((unsigned long long *)(b)      ),	\
	*((unsigned long long *)(r) + 0x1) = *((unsigned long long *)(a) + 0x1) ^ *((unsigned long long *)(b) + 0x1)
#elif defined(__i386__) || defined(_M_IX86)
#define XOR8x16(r, a, b)																		\
	*((unsigned int *)(r)      ) = *((unsigned int *)(a)      ) ^ *((unsigned int *)(b)      ),	\
	*((unsigned int *)(r) + 0x1) = *((unsigned int *)(a) + 0x1) ^ *((unsigned int *)(b) + 0x1),	\
	*((unsigned int *)(r) + 0x2) = *((unsigned int *)(a) + 0x2) ^ *((unsigned int *)(b) + 0x2),	\
	*((unsigned int *)(r) + 0x3) = *((unsigned int *)(a) + 0x3) ^ *((unsigned int *)(b) + 0x3)
#else
#define XOR8x16(r, a, b)				\
	*((r)      ) = *((a)      ) ^ *((b)      ),	\
	*((r) + 0x1) = *((a) + 0x1) ^ *((b) + 0x1),	\
	*((r) + 0x2) = *((a) + 0x2) ^ *((b) + 0x2),	\
	*((r) + 0x3) = *((a) + 0x3) ^ *((b) + 0x3),	\
	*((r) + 0x4) = *((a) + 0x4) ^ *((b) + 0x4),	\
	*((r) + 0x5) = *((a) + 0x5) ^ *((b) + 0x5),	\
	*((r) + 0x6) = *((a) + 0x6) ^ *((b) + 0x6),	\
	*((r) + 0x7) = *((a) + 0x7) ^ *((b) + 0x7),	\
	*((r) + 0x8) = *((a) + 0x8) ^ *((b) + 0x8),	\
	*((r) + 0x9) = *((a) + 0x9) ^ *((b) + 0x9),	\
	*((r) + 0xa) = *((a) + 0xa) ^ *((b) + 0xa),	\
	*((r) + 0xb) = *((a) + 0xb) ^ *((b) + 0xb),	\
	*((r) + 0xc) = *((a) + 0xc) ^ *((b) + 0xc),	\
	*((r) + 0xd) = *((a) + 0xd) ^ *((b) + 0xd),	\
	*((r) + 0xe) = *((a) + 0xe) ^ *((b) + 0xe),	\
	*((r) + 0xf) = *((a) + 0xf) ^ *((b) + 0xf)
#endif

#if defined(_MSC_VER) 
	#define INLINE		__forceinline
	#define ALIGN64		__declspec(align(64))
#elif defined(__GNUC__)
	#define INLINE		inline __attribute__((always_inline))
	#define ALIGN64		__attribute__ ((aligned(64)))
#elif defined(__sun) && defined(__SVR4)
	#define __attribute__(x)
	#define INLINE 		
	#define ALIGN64		__attribute__ ((aligned(64)))
#else
	#define INLINE 		__inline
	#define ALIGN64		__attribute__ ((aligned(64)))
#endif

#if defined _MSC_VER
	#include <stdlib.h>
	#define bswap64(x) _byteswap_uint64(x)
	#define bswap32(x) _byteswap_ulong(x)

//GCC 4.3 or later
#elif defined(__GNUC__) && (__GNUC__*100 + __GNUC_MINOR__*10 >= 430)
	#define bswap64(x) __builtin_bswap64(x)
	#define bswap32(x) __builtin_bswap32(x) 
#elif defined(__sun) && defined(__SVR4)
static U64 bswap64(U64 x) {
	x = ((x << 8) & 0xFF00FF00FF00FF00ULL) | ((x >> 8) & 0x00FF00FF00FF00FFULL);
	x = ((x << 16) & 0xFFFF0000FFFF0000ULL) | ((x >> 16) & 0x0000FFFF0000FFFFULL);
	return (x >> 32) | (x << 32);
}
	#define bswap32(x)  (((x)<<24) ^ ((x)>>24)^ (((x)&0xff00)<<8) ^ (((x)&0xff0000)>>8))
//in the other cases
#else
static __inline U64 bswap64(U64 x) {
	x = ((x << 8) & 0xFF00FF00FF00FF00ULL) | ((x >> 8) & 0x00FF00FF00FF00FFULL);
	x = ((x << 16) & 0xFFFF0000FFFF0000ULL) | ((x >> 16) & 0x0000FFFF0000FFFFULL);
	return (x >> 32) | (x << 32);
}
	#define bswap32(x)  (((x)<<24) ^ ((x)>>24)^ (((x)&0xff00)<<8) ^ (((x)&0xff0000)>>8))
#endif

/* bytearray-to-word, word-to-bytearray conversion */
/* can be processed faster on little-endian platforms*/
//x: array of bytes
#ifdef  LSH_BIG_ENDIAN
	#define U8TO64_LE(x)            (bswap64(*(U64*)(x)))
	#define U8TO32_LE(x)            (bswap32(*(U32*)(x)))
#else 
	#define U8TO64_LE(x)            (*(U64*)(x))
	#define U8TO32_LE(x)            (*(U32*)(x))
#endif

#define ROL32(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))

#define ROL64(x,n) (((x)<<(n))|((x)>>(64-(n))))
#define ROR64(x,n) (((x)>>(n))|((x)<<(64-(n))))

#ifdef __cplusplus
}
#endif

#endif
