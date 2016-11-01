#ifndef _LSH512_H_
#define _LSH512_H_

#include <stdlib.h>
#include "type.h"

#define NS512  28

#define LSH_LBLOCK				16
#define LSH384_DIGEST_LENGTH	48
#define LSH512_DIGEST_LENGTH	64
#define LSH512_CBLOCK			(LSH_LBLOCK*8)

#if defined(WIN32)
#define U64SUFFIX(C)     C##UI64
#elif defined(__arch64__)
#define U64SUFFIX(C)     C##UL
#else
#define U64SUFFIX(C)     C##ULL
#endif

typedef struct  
{
	int hashbitlen;    /* length of the hash value (bits) */
	/* 	variables for LSH-512-n 	*/
	U64 cv512[16];         /* current chain value */
	U8 Last512[256];     /* the last block for LSH-512-n */
} LSH512_CTX;

#ifdef __cplusplus
extern "C" {
#endif

/*
int SHA384_Init(SHA512_CTX *c);
int SHA384_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA384_Final(SHA512_CTX *c, unsigned char *md);
unsigned char *SHA384(const unsigned char *d, size_t n,unsigned char *md);
*/
void lsh512_init(LSH512_CTX *c);
void lsh512_update( LSH512_CTX *ctx, U8 *input, U32 length );
void lsh512_final( LSH512_CTX *ctx, U8 *digest);

void S_LSH512(U8 *out, U8 *in, U32 bytes);
//void S_LSH384(U8 *out, U8 *in, U32 bytes);

#ifdef __cplusplus
}
#endif

#endif

