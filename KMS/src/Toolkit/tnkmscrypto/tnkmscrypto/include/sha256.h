#ifndef _SHA256_H_
#define _SHA256_H_

#include <stdlib.h>
#include "type.h"

#define SHA256_DIGEST_LENGTH	32
#define SHA_LBLOCK				16
#define SHA_CBLOCK				(SHA_LBLOCK*4)

typedef struct
{
    U32 total[2];
    U32 state[8];
    U8 buffer[64];
	unsigned char xbuffer[104];

}
SHA256_CTX;

void sha256_init( SHA256_CTX *ctx );
void sha256_update( SHA256_CTX *ctx, U8 *input, U32 length );
void sha256_final( SHA256_CTX *ctx, U8 *digest);
void S_SHA256(U8 *out, U8 *in, U32 bytes);

#endif /* sha256.h */

