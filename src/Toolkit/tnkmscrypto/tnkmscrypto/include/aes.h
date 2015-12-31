/* version_4.0 */
#ifndef _AES_H
#define _AES_H

#include "type.h"

#if defined(_MSC_VER) && !defined(_M_IA64)
# define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
# define GETU32(p) SWAP(*((U32 *)(p)))
# define PUTU32(ct, st) { *((U32 *)(ct)) = SWAP((st)); }
#else
# define GETU32(pt) (((U32)(pt)[0] << 24) ^ ((U32)(pt)[1] << 16) ^ ((U32)(pt)[2] <<  8) ^ ((U32)(pt)[3]))
# define PUTU32(ct, st) { (ct)[0] = (U8)((st) >> 24); (ct)[1] = (U8)((st) >> 16); (ct)[2] = (U8)((st) >>  8); (ct)[3] = (U8)(st); }
#endif

/* Because array size can't be a const in C, the following two are macros.
   Both sizes are in bytes. */
#define MAXKC   (256/32)
#define MAXKB   (256/8)
#define MAXNR   14

#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16

#ifdef  __cplusplus
extern "C" {
#endif

/* This should be a hidden type, but EVP requires that the size be known */
struct aes_key_st {
    unsigned long rd_key[4 *(AES_MAXNR + 1)];
    int rounds;
};
typedef struct aes_key_st AES_KEY_ST;

const char *AES_options(void);

int S_AES_SET_Encrypt_Key(U8 *userKey, int bits, AES_KEY_ST *key) ;
int S_AES_SET_Decrypt_Key(U8 *userKey, int bits, AES_KEY_ST *key) ;

void S_AES_Encrypt(U8 *in, U8 *out, AES_KEY_ST *key) ;
void S_AES_Decrypt(U8 *in, U8 *out, AES_KEY_ST *key) ;

void S_AES_ECB_Encrypt(U8 *in, U8 *out, AES_KEY_ST *key) ;
void S_AES_ECB_Decrypt(U8 *in, U8 *out, AES_KEY_ST *key) ;

void S_AES_CBC_Encrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec) ;
void S_AES_CBC_Decrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec) ;

void S_AES_CFB128_Encrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec, unsigned int *num) ;
void S_AES_CFB128_Decrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec, unsigned int *num) ;

void S_AES_CFB1_Encrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec, unsigned int *num);
void S_AES_CFB1_Decrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec, unsigned int *num);

void S_AES_CFB8_Encrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec, unsigned int *num);
void S_AES_CFB8_Decrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec, unsigned int *num);

void S_AES_CFBR_Encrypt_Block(U8 *in, U8 *out, int nbits, AES_KEY_ST *key, U8 *ivec);
void S_AES_CFBR_Decrypt_Block(U8 *in, U8 *out, int nbits, AES_KEY_ST *key, U8 *ivec);

void S_AES_OFB128_Encrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec, unsigned int *num) ;
void S_AES_OFB128_Decrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec, unsigned int *num) ;

void S_AES_CTR128_Encrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 ivec[AES_BLOCK_SIZE], U8 ecount_buf[AES_BLOCK_SIZE], unsigned int *num) ;
void S_AES_CTR128_Decrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 ivec[AES_BLOCK_SIZE], U8 ecount_buf[AES_BLOCK_SIZE], unsigned int *num) ;

#ifdef  __cplusplus
}
#endif

#endif 
