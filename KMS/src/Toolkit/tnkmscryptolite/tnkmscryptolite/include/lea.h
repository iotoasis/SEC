#ifndef _LEA_H_
#define _LEA_H_

#include "type.h"

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef NO_LEA

#define LEA_BLOCK_SIZE			16
#define LEA_RNDKEY_WORD_SIZE	6

typedef struct lea_key_st
{
	unsigned int rk[192];
	unsigned int round;
} LEA_KEY;

int S_LEA_Keyschedule(LEA_KEY *key, const U8 *pbKey, unsigned int nKeyLen);
int S_LEA_Encrypt(LEA_KEY *key, const U8 *in, U8 *out);
int S_LEA_Decrypt(LEA_KEY *key, const U8 *in, U8 *out);

int S_LEA_ECB_Encrypt(LEA_KEY *key, const U8 *in, unsigned int in_len, U8 *out);
int S_LEA_ECB_Decrypt(LEA_KEY *key, const U8 *in, unsigned int in_len, U8 *out);

int S_LEA_CBC_Encrypt(LEA_KEY *key, U8 *ivec, const U8 *in, unsigned int in_len, U8 *out);
int S_LEA_CBC_Decrypt(LEA_KEY *key, U8 *ivec, const U8 *in, unsigned int in_len, U8 *out);

int S_LEA_CFB128_Encrypt(LEA_KEY *key, U8 *ivec, const U8 *in, unsigned int in_len, U8 *out);
int S_LEA_CFB128_Decrypt(LEA_KEY *key, U8 *ivec, const U8 *in, unsigned int in_len, U8 *out);

int S_LEA_CTR128_Encrypt(LEA_KEY *key, U8 *ctr, const U8 *in, unsigned int in_len, U8 *out);
int S_LEA_CTR128_Decrypt(LEA_KEY *key, U8 *ctr, const U8 *in, unsigned int in_len, U8 *out);

int S_LEA_OFB128_Encrypt(LEA_KEY *key, U8 *ivec, const U8 *in, unsigned int in_len, U8 *out);
int S_LEA_OFB128_Decrypt(LEA_KEY *key, U8 *ivec, const U8 *in, unsigned int in_len, U8 *out);

#endif // NO_LEA

#ifdef __cplusplus
}
#endif

#endif // _LEA_H_
