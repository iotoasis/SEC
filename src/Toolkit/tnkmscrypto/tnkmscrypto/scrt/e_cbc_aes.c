/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     e_aes.c  AES, CBC mode

	 Creadted by DEV3

************************************************/ 

#ifndef NO_AES
#include "../include/scrt.h"
#include "../include/aes.h"
#include <string.h>

static int S_aes_cbc_128_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int enc);
static int S_aes_cbc_192_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int enc);
static int S_aes_cbc_256_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int enc);

static void S_aes_cbc_cipher(SCRT_CIPHER_CTX *ctx, U8 *out, U8 *in, unsigned int inl);

/* 알고리즘의 특성에 알맞는 값들을 structure 구조에 저장 */
static SCRT_CIPHER d_cbc_128_aes=
{
	NID_aes_128_cbc, /* nid */
	16,  /* block length */
	16, /* key length */
	16,  /* iv length */
	S_aes_cbc_128_init_key, /* iv, key setting 함수 */
	S_aes_cbc_cipher,   /* 암복호화 함수 */
	NULL,				   /* 마무리 함수 */
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+ /* structure size */
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.aes_ks))
};

static SCRT_CIPHER d_cbc_192_aes=
{
	NID_aes_192_cbc, /* nid */
	16,  /* block length */
	24, /* key length */
	16,  /* iv length */
	S_aes_cbc_192_init_key, /* iv, key setting 함수 */
	S_aes_cbc_cipher,   /* 암복호화 함수 */
	NULL,				   /* 마무리 함수 */
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+ /* structure size */
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.aes_ks))
};

static SCRT_CIPHER d_cbc_256_aes=
{
	NID_aes_256_cbc, /* nid */
	16,  /* block length */
	32, /* key length */
	16,  /* iv length */
	S_aes_cbc_256_init_key, /* iv, key setting 함수 */
	S_aes_cbc_cipher,   /* 암복호화 함수 */
	NULL,				   /* 마무리 함수 */
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+ /* structure size */
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.aes_ks))
};

/* structure를 return 하는 함수 */
/*	
	Name : SCRT_aes_128_cbc
	Description: SCRT_CIPHER 구조체 d_cbc_128_aes 리턴 (키길이 128비트)
	Parameters
	Return Value : SCRT_CIPHER 구조체 d_cbc_128_aes 리턴 (키길이 128비트)
	Note :
*/
SCRT_CIPHER *SCRT_aes_128_cbc(void)
{
	return(&d_cbc_128_aes);
}
/*	
	Name : SCRT_aes_192_cbc
	Description: SCRT_CIPHER 구조체 d_cbc_192_aes 리턴 (키길이 192비트)
	Parameters
	Return Value : SCRT_CIPHER 구조체 d_cbc_192_aes 리턴 (키길이 192비트)
	Note :
*/
SCRT_CIPHER *SCRT_aes_192_cbc(void)
{
	return(&d_cbc_192_aes);
}

/*	
	Name : SCRT_aes_256_cbc
	Description: SCRT_CIPHER 구조체 d_cbc_256_aes 리턴 (키길이 256비트)
	Parameters
	Return Value : SCRT_CIPHER 구조체 d_cbc_256_aes 리턴 (키길이 256비트)
	Note :
*/
SCRT_CIPHER *SCRT_aes_256_cbc(void)
{
	return(&d_cbc_256_aes);
}

/*	
	Name : S_aes_cbc_128_init_key
	Description: 암호키 및 초기벡터를 이용하여 AES CBC 모드 암호알고리즘에 필요한 키 구조체 및 알고리즘 정보를 설정한다(키길이 128비트)
	Parameters
	[out] ctx : AES 암/복호화를 위한 AES_KEY 키 구조체 및 정보를 담은 구조체
	[in] key : 암호키 데이터
	[in] iv : 초기벡터
	[in] enc : 키구조체에 암호화키 설정는 1, 복호화 키설정은 0
	Return Value : 성공 1, 실패 0
	Note :
*/
static int S_aes_cbc_128_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int enc)
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
		ret = S_AES_SET_Decrypt_Key((U8 *)key,  128, &(ctx->c.aes_ks));
	}

	if(ret < 0) return 0;

	return 1;
}

/*	
	Name : S_aes_cbc_192_init_key
	Description: 암호키 및 초기벡터를 이용하여 AES CBC 모드 암호알고리즘에 필요한 키 구조체 및 알고리즘 정보를 설정한다(키길이 192비트)
	Parameters
	[out] ctx : AES 암/복호화를 위한 AES_KEY 키 구조체 및 정보를 담은 구조체
	[in] key : 암호키 데이터
	[in] iv : 초기벡터
	[in] enc : 키구조체에 암호화키 설정는 1, 복호화 키설정은 0
	Return Value : 성공 1, 실패 0
	Note :
*/
static int S_aes_cbc_192_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int enc)
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
		ret = S_AES_SET_Decrypt_Key((U8 *)key,  192, &(ctx->c.aes_ks));
	}

	if(ret < 0) return 0;

	return 1;
}

/*	
	Name : S_aes_cbc_256_init_key
	Description: 암호키 및 초기벡터를 이용하여 AES CBC 모드 암호알고리즘에 필요한 키 구조체 및 알고리즘 정보를 설정한다(키길이 256비트)
	Parameters
	[out] ctx : AES 암/복호화를 위한 AES_KEY 키 구조체 및 정보를 담은 구조체
	[in] key : 암호키 데이터
	[in] iv : 초기벡터
	[in] enc : 키구조체에 암호화키 설정는 1, 복호화 키설정은 0
	Return Value : 성공 1, 실패 0
	Note :
*/
static int S_aes_cbc_256_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int enc)
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
		ret = S_AES_SET_Decrypt_Key((U8 *)key,  256, &(ctx->c.aes_ks));
	}

	if(ret < 0) return 0;

	return 1;
}

/*	
	Name : S_aes_cbc_cipher
	Description: 암호키 및 초기벡터를 이용하여 AES CBC 모드 암호알고리즘을 이용하여 암/복호화 한다
	Parameters
	[in] ctx : AES 암/복호화를 위한 AES_KEY 키 구조체 및 정보를 담은 구조체
	[out] out : 암/복호화 된 데이터
	[in] in : 암/복호화 할 데이터
	[in] inl : 암/복호화 할 데이터 길이
	Return Value : 성공 1, 실패 0
	Note :
*/
static void S_aes_cbc_cipher(SCRT_CIPHER_CTX *ctx, U8 *out, U8 *in, unsigned int inl)
{
	if(ctx->encrypt) 
		S_AES_CBC_Encrypt(in, out, (long)inl, &(ctx->c.aes_ks), (U8 *)&(ctx->iv)) ;
	else
		S_AES_CBC_Decrypt(in, out, (long)inl, &(ctx->c.aes_ks), (U8 *)&(ctx->iv)) ;
}

#endif
