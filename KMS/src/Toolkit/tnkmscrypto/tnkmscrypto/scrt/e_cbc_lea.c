
/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     e_cbc_lea.c  LEA, CBC mode

	 Creadted by DEV3

************************************************/ 

#ifndef NO_ARIA

#include "../include/scrt.h"
#include "../include/lea.h"
#include <string.h>

static int S_lea_cbc_128_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int isenc);
static int S_lea_cbc_192_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int isenc);
static int S_lea_cbc_256_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int isenc);

static void S_lea_cbc_cipher(SCRT_CIPHER_CTX *ctx, U8 *out, U8 *in, unsigned int inl);

/* 알고리즘의 특성에 알맞는 값들을 structure 구조에 저장 */
static SCRT_CIPHER d_cbc_128_lea=
{
	NID_lea_128_cbc, /* nid */
	16,  /* block length */
	16,  /* key length */
	16,  /* iv length */
	S_lea_cbc_128_init_key, /* iv, key setting 함수 */
	S_lea_cbc_cipher,   /* 암복호화 함수 */
	NULL,				   /* 마무리 함수 */
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+ /* structure size */
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.lea_ks))
};

static SCRT_CIPHER d_cbc_192_lea=
{
	NID_lea_192_cbc, /* nid */
	16,  /* block length */
	24, /* key length */
	16,  /* iv length */
	S_lea_cbc_192_init_key, /* iv, key setting 함수 */
	S_lea_cbc_cipher,   /* 암복호화 함수 */
	NULL,				   /* 마무리 함수 */
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+ /* structure size */
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.lea_ks))
};

static SCRT_CIPHER d_cbc_256_lea=
{
	NID_lea_256_cbc, /* nid */
	16,  /* block length */
	32, /* key length */
	16,  /* iv length */
	S_lea_cbc_256_init_key, /* iv, key setting 함수 */
	S_lea_cbc_cipher,   /* 암복호화 함수 */
	NULL,				   /* 마무리 함수 */
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+ /* structure size */
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.lea_ks))
};

/*
	Name :  SCRT_lea_128_cbc
 	Description : LEA CBC 128bit 모드 암호알고리즘을 사용하기 위한 정보를 담은 구조체를 반환한다. 
 	Parameters
 	Return Value : d_cbc_128_lea 구조체를 반환한다.
 	Note :
 */
SCRT_CIPHER *SCRT_lea_128_cbc(void)
{
	return(&d_cbc_128_lea);
}

/*
	Name : SCRT_lea_192_cbc
 	Description : LEA CBC 192bit 모드 암호알고리즘을 사용하기 위한 정보를 담은 구조체를 반환한다. 
 	Parameters 
 	Return Value : d_cbc_192_lea 구조체를 반환한다.
 	Note :
 */
SCRT_CIPHER *SCRT_lea_192_cbc(void)
{
	return(&d_cbc_192_lea);
}

/*
	Name : SCRT_lea_256_cbc
 	Description : LEA CBC 256bit 모드 암호알고리즘을 사용하기 위한 정보를 담은 구조체를 반환한다. 
 	Parameters 
 	Return Value : d_cbc_256_lea 구조체를 반환한다.
 	Note :
 */
SCRT_CIPHER *SCRT_lea_256_cbc(void)
{
	return(&d_cbc_256_lea);
}

/*
	Name : S_lea_cbc_128_init_key
 	Description : 암호키 및 초기벡터를 이용하여 ARIA 128bit CBC 모드 암호 알고리즘에 필요한 키 구조체 및 알고리즘 정보를 설정한다.
 	Parameters
 	[out] ctx : ARIA 암/복호화를 위한 키 구조체 및 정보를 담은 구조체.
	[in] key : 암호키 데이터
	[in] iv : 초기벡터
	[in] isenc : 암/복호화 FLAG (1:enc, other : dec)
 	Return Value : 성공하였을 경우 1, 실패 하였을 경우 0
 	Note :
 */
static int S_lea_cbc_128_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int isenc)
{
	int ret ;
	if (iv != NULL)
		memcpy(&(ctx->oiv[0]),iv,16);

	memcpy(&(ctx->iv[0]),&(ctx->oiv[0]),16);  /* iv setting */

	if (isenc == 1)
		ret = S_LEA_Keyschedule(&(ctx->c.lea_ks), key, 16);
	else
		ret = S_LEA_Keyschedule(&(ctx->c.lea_ks), key, 16);

	if (ret < 0) return 0;

	return 1;
}

/*
	Name : S_aria_cbc_192_init_key
 	Description : 암호키 및 초기벡터를 이용하여 ARIA 192bit CBC 모드 암호 알고리즘에 필요한 키 구조체 및 알고리즘 정보를 설정한다.
 	Parameters
 	[out] ctx : ARIA 암/복호화를 위한 키 구조체 및 정보를 담은 구조체.
	[in] key : 암호키 데이터
	[in] iv : 초기벡터
	[in] isenc : 암/복호화 FLAG (1:enc, other : dec)
 	Return Value : 성공하였을 경우 1, 실패 하였을 경우 0
 	Note :
 */
static int S_lea_cbc_192_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int isenc)
{
	int ret ;
	if (iv != NULL)
		memcpy(&(ctx->oiv[0]),iv,16);

	memcpy(&(ctx->iv[0]),&(ctx->oiv[0]),16);  /* iv setting */

	if (isenc == 1)
		ret = S_LEA_Keyschedule(&(ctx->c.lea_ks), key, 24);
	else
		ret = S_LEA_Keyschedule(&(ctx->c.lea_ks), key, 24);
	
	if (ret < 0) return 0;
	
	return 1;
}

/*
	Name : S_lea_cbc_256_init_key
	Description : 암호키 및 초기벡터를 이용하여 LEA 256bit CBC 모드 암호 알고리즘에 필요한 키 구조체 및 알고리즘 정보를 설정한다.
	Parameters
	[out] ctx : LEA 암/복호화를 위한 키 구조체 및 정보를 담은 구조체.
	[in] key : 암호키 데이터
	[in] iv : 초기벡터
	[in] isenc : 암/복호화 여부 FLAG (1:enc, other : dec)
	Return Value : 성공하였을 경우 1, 그외의 경우 0
 	Note :
 */
static int S_lea_cbc_256_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int isenc)
{
	int ret ;
	if (iv != NULL)
		memcpy(&(ctx->oiv[0]),iv,16);

	memcpy(&(ctx->iv[0]),&(ctx->oiv[0]),16);  /* iv setting */

	if (isenc == 1)
		ret = S_LEA_Keyschedule(&(ctx->c.lea_ks), key, 32);
	else
		ret = S_LEA_Keyschedule(&(ctx->c.lea_ks), key, 32);
	
	if (ret < 0) return 0;
	
	return 1;
}

/*
	Name : S_aria_cbc_cipher
 	Description : 암호키 및 초기벡터 설정과 ARIA CBC 모드 암호 알고리즘을 이용하여 암/복호화 한다.
 	Parameters
 	[in] ctx : ARIA 암/복호화를 위한 키구조체 및 정보를 담은 구조체
	[out] out : 암/복호화 결과 데이터
	[in] in : 암/복호화 할 데이터
	[in] inl : 암/복호화 할 데이터 길이
 	Return Value :
 	Note :
 */
static void S_lea_cbc_cipher(SCRT_CIPHER_CTX *ctx, U8 *out, U8 *in, unsigned int inl)
{
	if (ctx->encrypt) 
		S_LEA_CBC_Encrypt(&(ctx->c.lea_ks), (U8 *)&(ctx->iv), in, inl, out);
	else
		S_LEA_CBC_Decrypt(&(ctx->c.lea_ks), (U8 *)&(ctx->iv), in, inl, out);
}

#endif
