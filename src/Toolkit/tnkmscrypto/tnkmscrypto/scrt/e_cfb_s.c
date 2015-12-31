
/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     e_cfb_s.c SEED, CFB mode

	 Creadted by DEV3

************************************************/

#ifndef NO_SEED

#include "../include/scrt.h"
#include "../include/seed.h"
#include <stdio.h>
#include <string.h>

static void S_seed_cfb_init_key(SCRT_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv);
static void S_seed_cfb_cipher(SCRT_CIPHER_CTX *ctx, unsigned char *out, unsigned char *in, unsigned int inl);

static SCRT_CIPHER s_cfb_cipher=
{
	NID_seed_cfb64,
	1,16,16,
	S_seed_cfb_init_key,
	S_seed_cfb_cipher,
	NULL,
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.seed_ks)),
};


/*	
	Name : SCRT_seed_cfb
	Description: SEED 알고리즘의 CFB 운영모드에서 사용할 사이퍼 구조체를 반환한다.
	Parameters
	Return Value : SEED 알고리즘 CFB 운영모드용 사이퍼 구조체
	Note : 
*/
SCRT_CIPHER *SCRT_seed_cfb(void)
{
	return(&s_cfb_cipher);
}

/*	
	Name : S_seed_cfb_init_key
	Description: SEED 알고리즘의 CFB 운영모드에서 사용할 키 구조체값을 생성한다.
	Parameters
	[in/out] ctx : 키 구조체값을 저장할 컨텍스트
	[in] key : 암호키 값
	[in] iv : 초기 벡터값
	Return Value : 
	Note : 
*/	
static void S_seed_cfb_init_key(SCRT_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv)
{
	ctx->num=0;

	if (iv != NULL)
		memcpy(&(ctx->oiv[0]),iv,16);
	memcpy(&(ctx->iv[0]),&(ctx->oiv[0]),16);

	S_SEED_KeySchedule(&(ctx->c.seed_ks),key);
}
	
/*	
	Name : S_seed_cfb_cipher
	Description: SEED 알고리즘의 CFB 운영모드로 암호화를 수행한다.
	Parameters
	[in] ctx : 키 구조체값을 저장하고 있는 컨텍스트
	[out] out : 암호화 결과값
	[in] in : 암호화 대상 원문값
	[in] inl : 암호화 대상 원문의 길이
	Return Value : 
	Note : 
*/	
static void S_seed_cfb_cipher(SCRT_CIPHER_CTX *ctx, unsigned char *out, unsigned char *in, unsigned int inl)
{
	if(ctx->encrypt)
		S_SEED_CFB_Encrypt(in,out,&(ctx->c.seed_ks),&(ctx->num),inl,(U8 *)&(ctx->iv));
	else
		S_SEED_CFB_Decrypt(in,out,&(ctx->c.seed_ks),&(ctx->num),inl,(U8 *)&(ctx->iv));
}

static void S_seed_cfb128_init_key(SCRT_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv);
static void S_seed_cfb128_cipher(SCRT_CIPHER_CTX *ctx, unsigned char *out, unsigned char *in, unsigned int inl);
static SCRT_CIPHER s_cfb128_cipher=
{
	NID_seed_cfb128,
	1,16,16,
	S_seed_cfb128_init_key,
	S_seed_cfb128_cipher,
	NULL,
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.seed_ks)),
};

/*	
	Name : SCRT_seed_cfb128
	Description: SEED 알고리즘의 CFB 운영모드에서 사용할 사이퍼 구조체를 반환한다.
	Parameters
	Return Value : SEED 알고리즘 CFB 운영모드용 사이퍼 구조체
	Note : 
*/
SCRT_CIPHER *SCRT_seed_cfb128(void)
{
	return(&s_cfb128_cipher);
}

/*	
	Name : S_seed_cfb128_init_key
	Description: SEED 알고리즘의 CFB 운영모드에서 사용할 키 구조체값을 생성한다.
	Parameters
	[in/out] ctx : 키 구조체값을 저장할 컨텍스트
	[in] key : 암호키 값
	[in] iv : 초기 벡터값
	Return Value : 
	Note : 
*/		
static void S_seed_cfb128_init_key(SCRT_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv)
{
	ctx->num=0;

	if (iv != NULL)
		memcpy(&(ctx->oiv[0]),iv,16);
	memcpy(&(ctx->iv[0]),&(ctx->oiv[0]),16);

	S_SEED_set_key_ex(key, &(ctx->c.seed_ks));
}
	

/*	
	Name : S_seed_cfb128_cipher
	Description: SEED 알고리즘의 CFB 운영모드로 암호화를 수행한다.
	Parameters
	[in] ctx : 키 구조체값을 저장하고 있는 컨텍스트
	[out] out : 암호화 결과값
	[in] in : 암호화 대상 원문값
	[in] inl : 암호화 대상 원문의 길이
	Return Value : 
	Note : 
*/
static void S_seed_cfb128_cipher(SCRT_CIPHER_CTX *ctx, unsigned char *out, unsigned char *in, unsigned int inl)
{
	if(ctx->encrypt)
		S_SEED_cfb128_encrypt_ex(in, out, inl, &(ctx->c.seed_ks), &(ctx->iv[0]), &(ctx->num));
	else
		S_SEED_cfb128_decrypt_ex(in, out, inl, &(ctx->c.seed_ks), &(ctx->iv[0]), &(ctx->num));
}

#endif
