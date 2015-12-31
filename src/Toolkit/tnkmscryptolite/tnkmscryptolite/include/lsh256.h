#ifndef _LSH256_H_
#define _LSH256_H_

#include <stdlib.h>
#include "type.h"

#define NS256  26
#define LSH256_DIGEST_LENGTH	32
#define LSH_LBLOCK				16
#define LSH_CBLOCK				(LSH_LBLOCK*4)

typedef struct  
{	
	int hashbitlen;    /* length of the hash value (bits) */	
						/* 	variables for LSH-256-n 	*/
	U32 cv256[16];         /* current chain value */
	U8 Last256[128];     /* the last block for LSH-256-n */	
} LSH256_CTX;

void lsh256_init( LSH256_CTX *ctx );
void lsh256_update( LSH256_CTX *ctx, U8 *input, U32 length );
void lsh256_final( LSH256_CTX *ctx, U8 *digest);
void S_LSH256(U8 *out, U8 *in, U32 bytes);

#endif /* lsh256.h */

