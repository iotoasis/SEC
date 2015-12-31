
/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     e_ecb_s.c SEED, ECB mode

	 Creadted by DEV3

************************************************/

#ifndef NO_SEED

#include "../include/scrt.h"
#include "../include/seed.h"
#include <stdio.h>
#include <string.h>

static void S_seed_ecb_init_key(SCRT_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv);
static void S_seed_ecb_cipher(SCRT_CIPHER_CTX *ctx, unsigned char *out,unsigned char *in, unsigned int inl);


static SCRT_CIPHER s_ecb_cipher=
{
	NID_seed_ecb,
	16,16,0,
	S_seed_ecb_init_key,
	S_seed_ecb_cipher,
	NULL,
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.seed_ks))
};

/*	
	Name : SCRT_seed_ecb
	Description: SEED 알고리즘의 ECB 운영모드에서 사용할 사이퍼 구조체를 반환한다.
	Parameters
	Return Value : SEED 알고리즘 ECB 운영모드용 사이퍼 구조체
	Note : 
*/
SCRT_CIPHER *SCRT_seed_ecb(void)
{
	return(&s_ecb_cipher);
}

/*	
	Name : S_seed_ecb_init_key
	Description: SEED 알고리즘의 ECB 운영모드에서 사용할 키 구조체값을 생성한다.
	Parameters
	[in/out] ctx : 키 구조체값을 저장할 컨텍스트
	[in] key : 암호키 값
	[in] iv : 초기 벡터값
	Return Value : 
	Note : 
*/		
static void S_seed_ecb_init_key(SCRT_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv)
{
		S_SEED_KeySchedule(&(ctx->c.seed_ks),key);
}

/*	
	Name : S_seed_ecb_cipher
	Description: SEED 알고리즘의 ECB 운영모드로 암호화를 수행한다.
	Parameters
	[in] ctx : 키 구조체값을 저장하고 있는 컨텍스트
	[out] out : 암호화 결과값
	[in] in : 암호화 대상 원문값
	[in] inl : 암호화 대상 원문의 길이
	Return Value : 
	Note : 
*/	
static void S_seed_ecb_cipher(SCRT_CIPHER_CTX *ctx, unsigned char *out, unsigned char *in, unsigned int inl)
{
		if(ctx->encrypt)
			S_SEED_ECB_Encrypt(in,out,&(ctx->c.seed_ks),inl);
		else
			S_SEED_ECB_Decrypt(in,out,&(ctx->c.seed_ks),inl);
}



#endif
