#ifndef __SCRT_H__
#define __SCRT_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "scrt_object.h"
#include "rand.h"
#include "scrt_error.h"
#include "typeconvert.h"

#ifndef NO_LEA
#include "lea.h"
#endif
#ifndef NO_LSH256
#include "lsh256.h"
#endif

#ifndef FREE
#define FREE(x) free(x);x = NULL
#endif

#define SCRT_MAX_MD_SIZE			(16+64)//(16+20)
#define SCRT_MAX_KEY_LENGTH			64
#define SCRT_MAX_IV_LENGTH			16 

#ifndef SCRT_MD
typedef struct env_md_st
{
	int type;        /* nid */
	int pkey_type;   /* hash+pkey nid */
	int md_size;     /* digest size */
	void (*init)();  /* init function pointer */
	void (*update)();/* hash function pointer */
	void (*final)(); /* final function pointer */

	int (*sign)();   /* sign function pointer */
	int (*verify)(); /* verify function pointer */
	int required_pkey_type[5]; /* pkey type */
	int block_size;  
	int ctx_size;    
} SCRT_MD;

#define SCRT_PKEY_NULL_method	NULL,NULL,{0,0,0,0}

#endif


typedef struct env_md_ctx_st
	{
	const SCRT_MD *digest;
	union	{
		unsigned char base[4];

#ifndef NO_LSH256
		LSH256_CTX lsh256;
#endif

		} md;
	} SCRT_MD_CTX;

typedef struct SCRT_cipher_st
{
	int nid;
	int block_size;
	int key_len;
	int iv_len;
	void (*init)();		
	void (*do_cipher)();
	void (*cleanup)();
	int ctx_size;
} SCRT_CIPHER;

typedef struct SCRT_cipher_ctx_st
{
	const SCRT_CIPHER *cipher;
	int encrypt;		
	int buf_len;		

	unsigned char oiv[SCRT_MAX_IV_LENGTH];	 /* original iv */
	unsigned char iv[SCRT_MAX_IV_LENGTH];	 /* using iv */
	unsigned char buf[SCRT_MAX_IV_LENGTH];	 
	int num;  /* cfb, ofb mode에서 선택 bits 에 사용 */

	union	{ /* key schedule */

#ifndef NO_LEA
		LEA_KEY lea_ks;
#endif
		} c;
} SCRT_CIPHER_CTX;


#if defined(WIN16) || defined(MSDOS)
#  define MS_STATIC	static
#else
#  define MS_STATIC
#endif

#define SCRT_CIPHER_key_length(e)	((e)->key_len)
#define SCRT_MD_block_size(e)		((e)->block_size)


/* EXPORT 함수 */

int SCRT_MD_CTX_copy(SCRT_MD_CTX *out,SCRT_MD_CTX *in);  
void SCRT_DigestInit(SCRT_MD_CTX *ctx, const SCRT_MD *type);
void SCRT_DigestUpdate(SCRT_MD_CTX *ctx,const void *d,unsigned int cnt);
void SCRT_DigestFinal(SCRT_MD_CTX *ctx,unsigned char *md,unsigned int *s);

/* HASH. */
SCRT_MD *SCRT_md_null(void);
SCRT_MD *SCRT_lsh256(void);

/*block e_null.c, e_cbc_d.c ... */
SCRT_CIPHER *SCRT_null();

SCRT_CIPHER *SCRT_seed_cbc(void);
SCRT_CIPHER *SCRT_seed_ncbc(void);
SCRT_CIPHER *SCRT_seed_ecb(void);
SCRT_CIPHER *SCRT_seed_cfb(void);
SCRT_CIPHER *SCRT_seed_ofb(void);
SCRT_CIPHER *SCRT_seed_ctr(void);
SCRT_CIPHER *SCRT_seed_cfb128(void);

SCRT_CIPHER *SCRT_seed256_cbc(void);
SCRT_CIPHER *SCRT_seed256_cfb(void);
SCRT_CIPHER *SCRT_seed256_ctr(void);
SCRT_CIPHER *SCRT_seed256_ecb(void);
SCRT_CIPHER *SCRT_seed256_ofb(void);

SCRT_CIPHER *SCRT_aes_128_cbc(void);
SCRT_CIPHER *SCRT_aes_192_cbc(void);
SCRT_CIPHER *SCRT_aes_256_cbc(void);

SCRT_CIPHER *SCRT_aes_128_cfb(void);
SCRT_CIPHER *SCRT_aes_192_cfb(void);
SCRT_CIPHER *SCRT_aes_256_cfb(void);

SCRT_CIPHER *SCRT_aes_128_ecb(void);
SCRT_CIPHER *SCRT_aes_192_ecb(void);
SCRT_CIPHER *SCRT_aes_256_ecb(void);

SCRT_CIPHER *SCRT_aes_128_ofb(void);
SCRT_CIPHER *SCRT_aes_192_ofb(void);
SCRT_CIPHER *SCRT_aes_256_ofb(void);

SCRT_CIPHER *SCRT_aes_128_ctr(void);
SCRT_CIPHER *SCRT_aes_192_ctr(void);
SCRT_CIPHER *SCRT_aes_256_ctr(void);

SCRT_CIPHER *SCRT_aria_128_cbc(void);
SCRT_CIPHER *SCRT_aria_192_cbc(void);
SCRT_CIPHER *SCRT_aria_256_cbc(void);

SCRT_CIPHER *SCRT_aria_128_cbc(void);
SCRT_CIPHER *SCRT_aria_192_cbc(void);
SCRT_CIPHER *SCRT_aria_256_cbc(void);

SCRT_CIPHER *SCRT_aria_128_cfb128(void);
SCRT_CIPHER *SCRT_aria_192_cfb128(void);
SCRT_CIPHER *SCRT_aria_256_cfb128(void);

SCRT_CIPHER *SCRT_aria_128_ecb(void);
SCRT_CIPHER *SCRT_aria_192_ecb(void);
SCRT_CIPHER *SCRT_aria_256_ecb(void);

SCRT_CIPHER *SCRT_aria_128_ofb128(void);
SCRT_CIPHER *SCRT_aria_192_ofb128(void);
SCRT_CIPHER *SCRT_aria_256_ofb128(void);

SCRT_CIPHER *SCRT_aria_128_ctr128(void);
SCRT_CIPHER *SCRT_aria_192_ctr128(void);
SCRT_CIPHER *SCRT_aria_256_ctr128(void);

//////////////////////////////////////////
SCRT_CIPHER *SCRT_lea_128_cbc(void);
SCRT_CIPHER *SCRT_lea_192_cbc(void);
SCRT_CIPHER *SCRT_lea_256_cbc(void);

SCRT_CIPHER *SCRT_lea_128_cfb128(void);
SCRT_CIPHER *SCRT_lea_192_cfb128(void);
SCRT_CIPHER *SCRT_lea_256_cfb128(void);

SCRT_CIPHER *SCRT_lea_128_ecb(void);
SCRT_CIPHER *SCRT_lea_192_ecb(void);
SCRT_CIPHER *SCRT_lea_256_ecb(void);

SCRT_CIPHER *SCRT_lea_128_ofb128(void);
SCRT_CIPHER *SCRT_lea_192_ofb128(void);
SCRT_CIPHER *SCRT_lea_256_ofb128(void);

SCRT_CIPHER *SCRT_lea_128_ctr128(void);
SCRT_CIPHER *SCRT_lea_192_ctr128(void);
SCRT_CIPHER *SCRT_lea_256_ctr128(void);

/* scrt_digest.c     */
int 	SCRT_MD_CTX_copy(SCRT_MD_CTX *out,SCRT_MD_CTX *in);  
void	SCRT_DigestInit(SCRT_MD_CTX *ctx, const SCRT_MD *type);
void	SCRT_DigestUpdate(SCRT_MD_CTX *ctx,const void *data, unsigned int count);
void	SCRT_DigestFinal(SCRT_MD_CTX *ctx,unsigned char *md,unsigned int *size);
int		SCRT_Digest(SCRT_MD_CTX *ctx, const void *in, unsigned int inl, unsigned char *out, unsigned int *outl);

/* scrt_enc.c */
SRESULT SCRT_Block_Encrypt(SCRT_CIPHER_CTX *ctx, U8 *in, int inl, U8 *keydata, U8 *iv, U8 *out, int *outl);
SRESULT SCRT_Block_Decrypt(SCRT_CIPHER_CTX *ctx, U8 *in, int inl, U8 *keydata, U8 *iv, U8 *out, int *outl);

SRESULT	SCRT_EncryptInit(SCRT_CIPHER_CTX *ctx,const SCRT_CIPHER *type,unsigned char *key, unsigned char *iv);
SRESULT	SCRT_EncryptUpdate(SCRT_CIPHER_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int inl);
SRESULT	SCRT_EncryptFinal(SCRT_CIPHER_CTX *ctx, unsigned char *out, int *outl);
SRESULT SCRT_EncryptFinal_MAC(SCRT_CIPHER_CTX *ctx, unsigned char *out, int *outl);

SRESULT	SCRT_DecryptInit(SCRT_CIPHER_CTX *ctx,const SCRT_CIPHER *type, unsigned char *key, unsigned char *iv);
SRESULT	SCRT_DecryptUpdate(SCRT_CIPHER_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int inl);
SRESULT	SCRT_DecryptFinal(SCRT_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
void	SCRT_CIPHER_CTX_init(SCRT_CIPHER_CTX *ctx);

/* m_null.c 등등.. m_ 함수. */
SCRT_MD *SCRT_md_null(void);
SCRT_MD *SCRT_sha256(void);
SCRT_MD *SCRT_sha512(void);
SCRT_MD *SCRT_lsh256(void);
SCRT_MD *SCRT_lsh512(void);

/* scrt_hmac.c */
SRESULT SCRT_HMAC(const SCRT_MD *SCRT_md, const void *key, int key_len, const unsigned char *data, int data_len, unsigned char *md, unsigned int *md_len);
SRESULT SCRT_HMAC2(const SCRT_MD *SCRT_md, const void *key, int key_len, const unsigned char *data, int data_len, unsigned char *md, unsigned int md_len);

/* scrt_rand.c */
SRESULT SCRT_GenerateRandom( U32 bytes, int mode,U8 *out);

#ifdef __cplusplus
}
#endif

#endif __SCRT_H__
