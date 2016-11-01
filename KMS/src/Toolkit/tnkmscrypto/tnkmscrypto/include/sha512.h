#ifndef _SHA512_H_
#define _SHA512_H_

#include <stdlib.h>
#include "type.h"

#define SHA_LBLOCK				16
#define SHA384_DIGEST_LENGTH	48
#define SHA512_DIGEST_LENGTH	64
#define SHA512_CBLOCK			(SHA_LBLOCK*8)

#define SHA512_CBLOCK	(SHA_LBLOCK*8)	/* SHA-512 treats input data as a contiguous array of 64 bit wide big-endian values. */

#if defined(WIN32)
#define U64SUFFIX(C)     C##UI64
#elif defined(__arch64__)
#define U64SUFFIX(C)     C##UL
#else
#define U64SUFFIX(C)     C##ULL
#endif

typedef struct SHA512state_st
{
	U64 h[8];
	U64 Nl,Nh;
	union {
		U64	d[SHA_LBLOCK];
		unsigned char	p[SHA512_CBLOCK];
	} u;
	unsigned int num,md_len;
} SHA512_CTX;

#ifdef __cplusplus
extern "C" {
#endif

int SHA384_Init(SHA512_CTX *c);
int SHA384_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA384_Final(SHA512_CTX *c, unsigned char *md);
unsigned char *SHA384(const unsigned char *d, size_t n,unsigned char *md);
int SHA512_Init(SHA512_CTX *c);
int SHA512_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA512_Final(SHA512_CTX *c, unsigned char *md);
unsigned char *SHA512(const unsigned char *d, size_t n,unsigned char *md);
void SHA512_Transform(SHA512_CTX *c, const unsigned char *data);

void S_SHA512(U8 *out, U8 *in, U32 bytes);
void S_SHA384(U8 *out, U8 *in, U32 bytes);

#ifdef __cplusplus
}
#endif

#endif

