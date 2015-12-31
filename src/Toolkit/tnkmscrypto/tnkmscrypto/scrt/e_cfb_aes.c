/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     e_cbc_aes.c AES, CFB mode

	 Creadted by DEV3

************************************************/ 

#ifndef NO_AES
#include "../include/scrt.h"
#include "../include/aes.h"
#include <string.h>
#include <math.h>

static int S_aes_cfb_128_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int enc);
static int S_aes_cfb_192_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int enc);
static int S_aes_cfb_256_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int enc);

static void S_aes_cfb_cipher(SCRT_CIPHER_CTX *ctx, U8 *out, U8 *in, unsigned int inl);

/* 알고리즘의 특성에 알맞는 값들을 structure 구조에 저장 */
static SCRT_CIPHER d_cfb_128_aes=
{
	NID_aes_128_cfb128, /* nid */
	1,  /* block length */
	16, /* key length */
	16,  /* iv length */
	S_aes_cfb_128_init_key, /* iv, key setting 함수 */
	S_aes_cfb_cipher,   /* 암복호화 함수 */
	NULL,				   /* 마무리 함수 */
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+ /* structure size */
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.aes_ks))
};

static SCRT_CIPHER d_cfb_192_aes=
{
	NID_aes_192_cfb128, /* nid */
	1,  /* block length */
	24, /* key length */
	16,  /* iv length */
	S_aes_cfb_192_init_key, /* iv, key setting 함수 */
	S_aes_cfb_cipher,   /* 암복호화 함수 */
	NULL,				   /* 마무리 함수 */
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+ /* structure size */
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.aes_ks))
};

static SCRT_CIPHER d_cfb_256_aes=
{
	NID_aes_256_cfb128, /* nid */
	1,  /* block length */
	32, /* key length */
	16,  /* iv length */
	S_aes_cfb_256_init_key, /* iv, key setting 함수 */
	S_aes_cfb_cipher,   /* 암복호화 함수 */
	NULL,				   /* 마무리 함수 */
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+ /* structure size */
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.aes_ks))
};

/* structure를 return 하는 함수 */
/*	
	Name : SCRT_aes_128_cfb
	Description: 128비트 키를 사용하는 AES 알고리즘의 CFB 운영모드에서 사용할 사이퍼 구조체를 반환한다.
	Parameters
	Return Value : AES 알고리즘의 CFB 운영모드용 사이퍼 구조체
	Note : 
*/
SCRT_CIPHER *SCRT_aes_128_cfb(void)
{
	return(&d_cfb_128_aes);
}

/*	
	Name : SCRT_aes_192_cfb
	Description: 192비트 키를 사용하는 AES 알고리즘의 CFB 운영모드에서 사용할 사이퍼 구조체를 반환한다.
	Parameters
	Return Value : AES 알고리즘의 CFB 운영모드용 사이퍼 구조체
	Note : 
*/
SCRT_CIPHER *SCRT_aes_192_cfb(void)
{
	return(&d_cfb_192_aes);
}

/*	
	Name : SCRT_aes_256_cfb
	Description: 256비트 키를 사용하는 AES 알고리즘의 CFB 운영모드에서 사용할 사이퍼 구조체를 반환한다.
	Parameters
	Return Value : AES 알고리즘의 CFB 운영모드용 사이퍼 구조체
	Note : 
*/
SCRT_CIPHER *SCRT_aes_256_cfb(void)
{
	return(&d_cfb_256_aes);
}

/*	
	Name : S_aes_cfb_128_init_key
	Description: 128비트 키를 사용하는 AES 알고리즘의 CFB 운영모드에서 사용할 키 구조체값을 생성한다.
	Parameters
	[in/out] ctx : 키 구조체값을 저장할 컨텍스트
	[in] key : 암호키 값
	[in] iv : 초기 벡터값
	[in] enc : 암호화인지 복호화인지 여부. 1이면 암호화. 0이면 복호화
	Return Value : 초기화에 성공하면 1
	               초기화에 실패하면 0
	Note : 
*/	
static int S_aes_cfb_128_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int enc)
{
	int ret ;
	if (iv != NULL)
		memcpy(&(ctx->oiv[0]),iv,16);

	memcpy(&(ctx->iv[0]),&(ctx->oiv[0]),16);  /* iv setting */

	if(enc)
	{
		ret = S_AES_SET_Encrypt_Key((U8 *)key,  128, &(ctx->c.aes_ks));
	}else
	{
		ret = S_AES_SET_Encrypt_Key((U8 *)key,  128, &(ctx->c.aes_ks));
	}

	if(ret < 0) return 0;

	return 1;
}

/*	
	Name : S_aes_cfb_192_init_key
	Description: 192비트 키를 사용하는 AES 알고리즘의 CFB 운영모드에서 사용할 키 구조체값을 생성한다.
	Parameters
	[in/out] ctx : 키 구조체값을 저장할 컨텍스트
	[in] key : 암호키 값
	[in] iv : 초기 벡터값
	[in] enc : 암호화인지 복호화인지 여부. 1이면 암호화. 0이면 복호화
	Return Value : 초기화에 성공하면 1
	               초기화에 실패하면 0
	Note : 
*/
static int S_aes_cfb_192_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int enc)
{
	int ret ;
	if (iv != NULL)
		memcpy(&(ctx->oiv[0]),iv,16);

	memcpy(&(ctx->iv[0]),&(ctx->oiv[0]),16);  /* iv setting */

	if(enc)
	{
		ret = S_AES_SET_Encrypt_Key((U8 *)key,  192, &(ctx->c.aes_ks));
	}else
	{
		ret = S_AES_SET_Encrypt_Key((U8 *)key,  192, &(ctx->c.aes_ks));
	}

	if(ret < 0) return 0;

	return 1;
}

/*	
	Name : S_aes_cfb_256_init_key
	Description: 256비트 키를 사용하는 AES 알고리즘의 CFB 운영모드에서 사용할 키 구조체값을 생성한다.
	Parameters
	[in/out] ctx : 키 구조체값을 저장할 컨텍스트
	[in] key : 암호키 값
	[in] iv : 초기 벡터값
	[in] enc : 암호화인지 복호화인지 여부. 1이면 암호화. 0이면 복호화
	Return Value : 초기화에 성공하면 1
	               초기화에 실패하면 0
	Note : 
*/
static int S_aes_cfb_256_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int enc)
{
	int ret ;
	if (iv != NULL)
		memcpy(&(ctx->oiv[0]),iv,16);

	memcpy(&(ctx->iv[0]),&(ctx->oiv[0]),16);  /* iv setting */

	if(enc)
	{
		ret = S_AES_SET_Encrypt_Key((U8 *)key,  256, &(ctx->c.aes_ks));
	}else
	{
		ret = S_AES_SET_Encrypt_Key((U8 *)key,  256, &(ctx->c.aes_ks));
	}

	if(ret < 0) return 0;

	return 1;
}

/*	
	Name : S_aes_cfb_cipher
	Description: AES 알고리즘의 CFB 운영모드에서 데이터를 암/복호화한다.
	Parameters
	[in/out] ctx : 암호키가 저장되어 있는 컨텍스트
	[out] out : 암호화 결과값
	[in] in : 암호화 대상 원문값
	[in] inl : 암호화 대상 원문값의 길이
	Return Value :
	Note : 
*/
static void S_aes_cfb_cipher(SCRT_CIPHER_CTX *ctx, U8 *out, U8 *in, unsigned int inl)
{
	if(ctx->encrypt) 
	{
		int num =0;

		S_AES_CFB128_Encrypt(in, out, (long)inl, &(ctx->c.aes_ks), (U8 *)&(ctx->iv), &num) ;
	}
	else
	{
		int num =0;

		S_AES_CFB128_Decrypt(in, out, (long)inl, &(ctx->c.aes_ks), (U8 *)&(ctx->iv), &num) ;
	}

}
#endif
