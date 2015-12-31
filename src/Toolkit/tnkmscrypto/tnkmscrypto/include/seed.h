#ifndef _SEED_H_
#define _SEED_H_

/* I/O : 128 Bit
   Key Data : 128 Bit */
   
#include <stdlib.h>
#include "type.h"

#define SEED_BLOCK_SIZE 16

#if defined(_MSC_VER) && !defined(_M_IA64)
# define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
# define GETU32(p) SWAP(*((U32 *)(p)))
# define PUTU32(ct, st) { *((U32 *)(ct)) = SWAP((st)); }
#else
# define GETU32(pt) (((U32)(pt)[0] << 24) ^ ((U32)(pt)[1] << 16) ^ ((U32)(pt)[2] <<  8) ^ ((U32)(pt)[3]))
# define PUTU32(ct, st) { (ct)[0] = (U8)((st) >> 24); (ct)[1] = (U8)((st) >> 16); (ct)[2] = (U8)((st) >>  8); (ct)[3] = (U8)(st); }
#endif

#define B0(x)  ( (U8)((x)    ) )
#define B1(x)  ( (U8)((x)>> 8) )
#define B2(x)  ( (U8)((x)>>16) )
#define B3(x)  ( (U8)((x)>>24) )

#ifndef WIN32
#define _lrotl(x, n) (((x) << (n)) | ((x) >> (32-(n))))
#define _lrotr(x, n) (((x) >> (n)) | ((x) << (32-(n))))
#endif

#define Reverse(d) \
{ \
	T0=d; \
	d=((_lrotl(T0,8)&0x00FF00FF)|(_lrotl(T0,24)&0xFF00FF00)); \
}


#define SEED_ROUND(L0, L1, R0, R1) \
{ \
	T1 ^= T0; \
	T1 = SS0[B0(T1)] ^ SS1[B1(T1)] ^ SS2[B2(T1)] ^ SS3[B3(T1)]; \
	T0 += T1; \
	T0 = SS0[B0(T0)] ^ SS1[B1(T0)] ^ SS2[B2(T0)] ^ SS3[B3(T0)]; \
	T1 += T0; \
	T1 = SS0[B0(T1)] ^ SS1[B1(T1)] ^ SS2[B2(T1)] ^ SS3[B3(T1)]; \
	T0 += T1; \
	L0 ^= T0; \
	L1 ^= T1; \
}

#define SEED_ENC(L0, L1, R0, R1) \
{ \
	T0 = R0 ^ *(k++); \
	T1 = R1 ^ *(k++); \
	SEED_ROUND(L0, L1, R0, R1); \
}

#define SEED_DEC(L0, L1, R0, R1) \
{ \
	T1 = R1 ^ *(k--); \
	T0 = R0 ^ *(k--); \
	SEED_ROUND(L0, L1, R0, R1); \
}

#define SEED_ROTR \
{ \
	t = A; \
	A = (A >> 8) ^ (B << 24); \
	B = (B >> 8) ^ (t << 24); \
}

#define SEED_ROTL \
{ \
	t = C; \
	C = (C << 8) ^ (D >> 24); \
	D = (D << 8) ^ (t >> 24); \
}

#define SEED_KEYROUND \
{ \
	T0 = A + C - *kc; \
	T1 = B - D + *(kc++); \
	*(k++) = SS0[B0(T0)] ^ SS1[B1(T0)] ^ SS2[B2(T0)] ^ SS3[B3(T0)]; \
	*(k++) = SS0[B0(T1)] ^ SS1[B1(T1)] ^ SS2[B2(T1)] ^ SS3[B3(T1)]; \
}

#define SEED_KEYROUND0 \
{ \
	SEED_KEYROUND; \
	SEED_ROTR; \
}

#define SEED_KEYROUND1 \
{ \
	SEED_KEYROUND; \
	SEED_ROTL; \
}

typedef struct seed_key_struct
{
	U32 data[32];
} SEED_KEY;

#ifdef __cplusplus
extern "C"
{
#endif

void S_SEED_Encrypt(U32 *data, SEED_KEY *key);
void S_SEED_Decrypt(U32 *data, SEED_KEY *key);
void S_SEED_KeySchedule(SEED_KEY *key, U8 *data);

void S_SEED_set_key_ex(const unsigned char rawkey[16], SEED_KEY *ks);
void S_SEED_encrypt_ex(const unsigned char s[SEED_BLOCK_SIZE], unsigned char d[SEED_BLOCK_SIZE], const SEED_KEY *ks);
void S_SEED_decrypt_ex(const unsigned char s[SEED_BLOCK_SIZE], unsigned char d[SEED_BLOCK_SIZE], const SEED_KEY *ks);

void S_SEED_ECB_Encrypt(U8 *in, U8 *out, SEED_KEY *key, long bytes);
void S_SEED_ECB_Decrypt(U8 *in, U8 *out, SEED_KEY *key, long bytes);

void S_SEED_CBC_Encrypt(U8 *in, U8 *out, SEED_KEY *key, long bytes, U8 *iv);
void S_SEED_CBC_Decrypt(U8 *in, U8 *out, SEED_KEY *key, long bytes, U8 *iv);

void S_SEED_CFB_Encrypt(U8 *in, U8 *out, SEED_KEY *key, int *numbits, long bytes, U8 *iv);
void S_SEED_CFB_Decrypt(U8 *in, U8 *out, SEED_KEY *key, int *numbits, long bytes, U8 *iv);

void S_SEED_cfb128_encrypt_ex(const unsigned char *in, unsigned char *out, size_t len, const SEED_KEY *ks, unsigned char ivec[SEED_BLOCK_SIZE], int *num);
void S_SEED_cfb128_decrypt_ex(const unsigned char *in, unsigned char *out, size_t len, const SEED_KEY *ks, unsigned char ivec[SEED_BLOCK_SIZE], int *num);

void S_SEED_OFB_Encrypt(U8 *in, U8 *out, SEED_KEY *key, int *numbits, long bytes, U8 *iv);
void S_SEED_OFB_Decrypt(U8 *in, U8 *out, SEED_KEY *key, int *numbits, long bytes, U8 *iv);

void S_SEED_CTR128_Encrypt(U8 *in, U8 *out, U32 length, SEED_KEY *key, U8 ivec[SEED_BLOCK_SIZE], U8 ecount_buf[SEED_BLOCK_SIZE], unsigned int *num) ;
void S_SEED_CTR128_Decrypt(U8 *in, U8 *out, U32 length, SEED_KEY *key, U8 ivec[SEED_BLOCK_SIZE], U8 ecount_buf[SEED_BLOCK_SIZE], unsigned int *num) ;

#ifdef __cplusplus
}
#endif

#endif
