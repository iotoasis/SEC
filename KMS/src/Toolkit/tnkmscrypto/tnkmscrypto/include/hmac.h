#ifndef _HMAC_H_
#define _HMAC_H_

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef NO_HMAC
#error HMAC is disabled.
#endif

#include "scrt.h"

#define HMAC_MAX_MD_CBLOCK	256

typedef struct hmac_ctx_st
{
	const SCRT_MD *md;
	SCRT_MD_CTX md_ctx;
	SCRT_MD_CTX i_ctx;
	SCRT_MD_CTX o_ctx;
	unsigned int key_length;
	unsigned char key[HMAC_MAX_MD_CBLOCK];
} HMAC_CTX;

#define HMAC_size(e)	(SCRT_MD_size((e)->md))

void S_HMAC_Init(HMAC_CTX *ctx, const void *key, int len, const SCRT_MD *md);
void S_HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, int len);
void S_HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
void S_HMAC_cleanup(HMAC_CTX *ctx);

#ifdef  __cplusplus
}
#endif

#endif
