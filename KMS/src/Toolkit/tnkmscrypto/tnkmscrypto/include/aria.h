#ifndef _ARIA_H_
#define _ARIA_H_

#include "type.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define ARIA_BLOCK_SIZE 16

typedef struct 
{
	U8 rd_key[272];
	U32 keyBits;
} ARIA_KEY;


int  S_ARIA_Encrypt_KeySchedule(ARIA_KEY *key, const U8 *mk, int keyBits);
int  S_ARIA_Decrypt_KeySchedule(ARIA_KEY *key, const U8 *mk, int keyBits);
void S_ARIA_Encrypt(ARIA_KEY *key, const U8 *in, U8 *out);
void S_ARIA_Decrypt(ARIA_KEY *key, const U8 *in, U8 *out);

void S_ARIA_ECB_Encrypt(ARIA_KEY *key, U8 *in, int inbytes, U8 *out);
void S_ARIA_ECB_Decrypt(ARIA_KEY *key, U8 *in, int inbytes, U8 *out);

void S_ARIA_CBC_Encrypt(ARIA_KEY *key, U8 *ivec, U8 *in, int inbytes, U8 *out);
void S_ARIA_CBC_Decrypt(ARIA_KEY *key, U8 *ivec, U8 *in, int inbytes, U8 *out);

void S_ARIA_CFB128_Encrypt(ARIA_KEY *key, U8 *ivec, U8 *in, int inbytes, U8 *out, int *numbits);
void S_ARIA_CFB128_Decrypt(ARIA_KEY *key, U8 *ivec, U8 *in, int inbytes, U8 *out, int *numbits);

void S_ARIA_OFB128_Encrypt(ARIA_KEY *key, U8 *ivec, U8 *in, unsigned int inbytes, U8 *out, int *numbits);
void S_ARIA_OFB128_Decrypt(ARIA_KEY *key, U8 *ivec, U8 *in, unsigned int inbytes, U8 *out, int *numbits);

void S_ARIA_CTR128_Encrypt(ARIA_KEY *key, U8 *ivec, U8 *in, unsigned int inbytes, U8 *out, U8 *ecount_buf, int *numbits);
void S_ARIA_CTR128_Decrypt(ARIA_KEY *key, U8 *ivec, U8 *in, unsigned int inbytes, U8 *out, U8 *ecount_buf, int *numbits);

#ifdef __cplusplus
}
#endif

#endif // _ARIA_H_
