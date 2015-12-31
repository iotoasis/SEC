
/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     e_cbc_aria.c  ARIA, CBC mode

	 Creadted by DEV3

************************************************/ 

#ifndef NO_ARIA

#include "../include/scrt.h"
#include "../include/aria.h"
#include <string.h>
#include <math.h>

static int S_aria_cfb128_128_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int isenc);
static int S_aria_cfb128_192_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int isenc);
static int S_aria_cfb128_256_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int isenc);

static void S_aria_cfb128_cipher(SCRT_CIPHER_CTX *ctx, U8 *out, U8 *in, unsigned int inl);

/* ARIA 128bit CFB128 모드 알고리즘의 특성에 알맞는 값들을 structure 구조에 저장 */
static SCRT_CIPHER d_cfb128_128_aria=
{
	NID_aria_128_cfb128, /* nid */
	1,  /* block length */
	16, /* key length */
	16,  /* iv length */
	S_aria_cfb128_128_init_key, /* iv, key setting 함수 */
	S_aria_cfb128_cipher,   /* 암복호화 함수 */
	NULL,				   /* 마무리 함수 */
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+ /* structure size */
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.aria_ks))
};

/* ARIA 192bit CFB128 모드 알고리즘의 특성에 알맞는 값들을 structure 구조에 저장 */
static SCRT_CIPHER d_cfb128_192_aria=
{
	NID_aria_192_cfb128, /* nid */
	1,  /* block length */
	24, /* key length */
	16,  /* iv length */
	S_aria_cfb128_192_init_key, /* iv, key setting 함수 */
	S_aria_cfb128_cipher,   /* 암복호화 함수 */
	NULL,				   /* 마무리 함수 */
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+ /* structure size */
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.aria_ks))
};

/* ARIA 256bit CFB128 모드 알고리즘의 특성에 알맞는 값들을 structure 구조에 저장 */
static SCRT_CIPHER d_cfb128_256_aria=
{
	NID_aria_256_cfb128, /* nid */
	1,  /* block length */
	32, /* key length */
	16,  /* iv length */
	S_aria_cfb128_256_init_key, /* iv, key setting 함수 */
	S_aria_cfb128_cipher,   /* 암복호화 함수 */
	NULL,				   /* 마무리 함수 */
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+ /* structure size */
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.aria_ks))
};

/* structure를 return 하는 함수 */
/*	
	Name : SCRT_aria_128_cfb128
	Description: ARIA 128 bit CFB128 모드 암호알고리즘을 사용하기 위한 정보를 담은 구조체를 반환한다
	Parameters
	Return Value : d_cfb128_128_aria 구조체를 반환한다
	Note :
*/
SCRT_CIPHER *SCRT_aria_128_cfb128(void)
{
	return(&d_cfb128_128_aria);
}

/*	
	Name : SCRT_aria_192_cfb128
	Description: ARIA 192 bit CFB128 모드 암호알고리즘을 사용하기 위한 정보를 담은 구조체를 반환한다
	Parameters
	Return Value : d_cfb128_192_aria 구조체를 반환한다
	Note :
*/
SCRT_CIPHER *SCRT_aria_192_cfb128(void)
{
	return(&d_cfb128_192_aria);
}

/*	
	Name : SCRT_aria_256_cfb128
	Description: ARIA 256 bit CFB128 모드 암호알고리즘을 사용하기 위한 정보를 담은 구조체를 반환한다
	Parameters
	Return Value : d_cfb128_256_aria 구조체를 반환한다
	Note :
*/
SCRT_CIPHER *SCRT_aria_256_cfb128(void)
{
	return(&d_cfb128_256_aria);
}

/*	
	Name : S_aria_cfb128_128_init_key
	Description: 암호키 및 초기벡터를 이용하여 ARIA 128bit CFB128 모드 암호알고리즘에 필요한 키 구조체 및 알고리즘 정보를 설정한다
	Parameters
	[out] ctx : ARIA 암/복호화를 위한 ARIA_KEY 키 구조체 및 정보를 담은 구조체
	[in] key : 암호키 데이터
	[in] iv : 초기벡터
	[in] isenc : 암/복호화 여부 FLAG ( 1 : 암호화 , 그외 : 복호화 )
	Return Value : 성공하였을 경우 1, 그외의 경우 0 값을 반환한다
	Note :
*/
static int S_aria_cfb128_128_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int isenc)
{
	int ret ;

	ctx->num=0;

	if (iv != NULL)
		memcpy(&(ctx->oiv[0]),iv,16);

	memcpy(&(ctx->iv[0]),&(ctx->oiv[0]),16);  /* iv setting */

	if (isenc == 1)
		ret = S_ARIA_Encrypt_KeySchedule(&(ctx->c.aria_ks), key, 128);
	else
		ret = S_ARIA_Encrypt_KeySchedule(&(ctx->c.aria_ks), key, 128);
	
	if (ret < 0) return 0;
	
	return 1;
}

/*	
	Name : S_aria_cfb128_192_init_key
	Description: 암호키 및 초기벡터를 이용하여 ARIA 192bit CFB128 모드 암호알고리즘에 필요한 키 구조체 및 알고리즘 정보를 설정한다
	Parameters
	[out] ctx : ARIA 암/복호화를 위한 ARIA_KEY 키 구조체 및 정보를 담은 구조체
	[in] key : 암호키 데이터
	[in] iv : 초기벡터
	[in] isenc : 암/복호화 여부 FLAG ( 1 : 암호화 , 그외 : 복호화 )
	Return Value : 성공하였을 경우 1, 그외의 경우 0 값을 반환한다
	Note :
*/
static int S_aria_cfb128_192_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int isenc)
{
	int ret ;

	ctx->num=0;

	if (iv != NULL)
		memcpy(&(ctx->oiv[0]),iv,16);

	memcpy(&(ctx->iv[0]),&(ctx->oiv[0]),16);  /* iv setting */

	if (isenc == 1)
		ret = S_ARIA_Encrypt_KeySchedule(&(ctx->c.aria_ks), key, 192);
	else
		ret = S_ARIA_Encrypt_KeySchedule(&(ctx->c.aria_ks), key, 192);
	
	if (ret < 0) return 0;
	
	return 1;
}

/*	
	Name : S_aria_cfb128_256_init_key
	Description: 암호키 및 초기벡터를 이용하여 ARIA 256bit CFB128 모드 암호알고리즘에 필요한 키 구조체 및 알고리즘 정보를 설정한다
	Parameters
	[out] ctx : ARIA 암/복호화를 위한 ARIA_KEY 키 구조체 및 정보를 담은 구조체
	[in] key : 암호키 데이터
	[in] iv : 초기벡터
	[in] isenc : 암/복호화 여부 FLAG ( 1 : 암호화 , 그외 : 복호화 )
	Return Value : 성공하였을 경우 1, 그외의 경우 0 값을 반환한다
	Note :
*/
static int S_aria_cfb128_256_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int isenc)
{
	int ret ;

	ctx->num=0;

	if (iv != NULL)
		memcpy(&(ctx->oiv[0]),iv,16);

	memcpy(&(ctx->iv[0]),&(ctx->oiv[0]),16);  /* iv setting */

	if (isenc == 1)
		ret = S_ARIA_Encrypt_KeySchedule(&(ctx->c.aria_ks), key, 256);
	else
		ret = S_ARIA_Encrypt_KeySchedule(&(ctx->c.aria_ks), key, 256);
	
	if (ret < 0) return 0;
	
	return 1;
}

/*	
	Name : S_aria_cfb128_cipher
	Description: 암호키 및 초기벡터를 이용하여 ARIA CFB128 모드 암호알고리즘을 이용하여 입력/암호화된 데이터를 암/복호화 한다
	Parameters
	[in] ctx : ARIA 암/복호화를 위한 ARIA_KEY 키 구조체 및 정보를 담은 구조체
	[out] out : 암/복호화 된 데이터
	[in] in : 암/복호화 할 데이터
	[in] inl : 암/복호화 할 데이터 길이
	Return Value : 
	Note :
*/
static void S_aria_cfb128_cipher(SCRT_CIPHER_CTX *ctx, U8 *out, U8 *in, unsigned int inl)
{
	if (ctx->encrypt) 
		S_ARIA_CFB128_Encrypt(&(ctx->c.aria_ks), (U8 *)&(ctx->iv), in, inl, out, &(ctx->num));
	else
		S_ARIA_CFB128_Decrypt(&(ctx->c.aria_ks), (U8 *)&(ctx->iv), in, inl, out, &(ctx->num));
}
#endif
