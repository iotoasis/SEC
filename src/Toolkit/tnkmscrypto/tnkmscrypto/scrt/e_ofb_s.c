
/***********************************************
	 Copyright (C) 2015, UNETsystem
 
      e_ofb_s.c SEED, OFB mode

	 Creadted by DEV3

************************************************/

#ifndef NO_SEED

#include "../include/scrt.h"
#include "../include/seed.h"
#include <stdio.h>
#include <string.h>

static void S_seed_ofb_init_key(SCRT_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv);
static void S_seed_ofb_cipher(SCRT_CIPHER_CTX *ctx, unsigned char *out, unsigned char *in, unsigned int inl);

static SCRT_CIPHER s_ofb_cipher=
{
	NID_seed_ofb64,
	1, 16, 16,
	S_seed_ofb_init_key,
	S_seed_ofb_cipher,
	NULL,
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.seed_ks))
};


/*	
	Name : SCRT_seed_ofb
	Description: SEED OFB 모드 암호알고리즘을 사용하기 위한 정보를 담은 구조체를 반환한다
	Parameters
	Return Value : s_ofb_cipher 구조체를 반환한다
	Note :
*/
SCRT_CIPHER *SCRT_seed_ofb(void)
{
	return(&s_ofb_cipher);
}
	
/*	
	Name : S_seed_ofb_init_key
	Description: 암호키를 이용하여 SEED OFB 모드 암호알고리즘에 필요한 키 구조체 및 알고리즘 정보를 설정한다
	Parameters
	[out] ctx : SEED 암/복호화를 위한 SEED_KEY 키 구조체 및 정보를 담은 구조체
	[in] key : 암호키 데이터
	[in] iv : 초기벡터
	Return Value : 
	Note :
*/		
static void S_seed_ofb_init_key(SCRT_CIPHER_CTX *ctx, unsigned char *key,unsigned char *iv)
{
	ctx->num=0;

	if (iv != NULL)
		memcpy(&(ctx->oiv[0]),iv,16);
	memcpy(&(ctx->iv[0]),&(ctx->oiv[0]),16);

	S_SEED_KeySchedule(&(ctx->c.seed_ks),key);
}
	
/*	
	Name : S_seed_ofb_cipher
	Description: 암호키를 이용하여 SEED OFB 모드 암호알고리즘을 이용하여 입력/암호화된 데이터를 암/복호화 한다
	Parameters
	[in] ctx : SEED 암/복호화를 위한 SEED_KEY 키 구조체 및 정보를 담은 구조체
	[out] out : 암/복호화 된 데이터
	[in] in : 암/복호화 할 데이터
	[in] inl : 암/복호화 할 데이터 길이
	Return Value : 
	Note :
*/
static void S_seed_ofb_cipher(SCRT_CIPHER_CTX *ctx, unsigned char *out, unsigned char *in, unsigned int inl)
{
	if(ctx->encrypt)
		S_SEED_OFB_Encrypt(in,out,&(ctx->c.seed_ks),&(ctx->num),inl,(U8 *)&(ctx->iv));
	else
		S_SEED_OFB_Decrypt(in,out,&(ctx->c.seed_ks),&(ctx->num),inl,(U8 *)&(ctx->iv));
}

#endif
