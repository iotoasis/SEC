
/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     e_aes.c  SEED, CTR mode

	 Creadted by DEV3

************************************************/

#ifndef NO_SEED

#include "../include/scrt.h"
#include "../include/seed.h"
#include <string.h>

static int S_seed_ctr_128_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int enc);
static void S_seed_ctr_cipher(SCRT_CIPHER_CTX *ctx, U8 *out, U8 *in, unsigned int inl);

/* 알고리즘의 특성에 알맞는 값들을 structure 구조에 저장 */
static SCRT_CIPHER d_ctr_128_seed=
{
	NID_seed_ctr128, /* nid */
	1,  /* block length */
	16, /* key length */
	16,  /* iv length */
	S_seed_ctr_128_init_key, /* iv, key setting 함수 */
	S_seed_ctr_cipher,   /* 암복호화 함수 */
	NULL,				   /* 마무리 함수 */
	sizeof(SCRT_CIPHER_CTX)-sizeof((((SCRT_CIPHER_CTX *)NULL)->c))+ /* structure size */
		sizeof((((SCRT_CIPHER_CTX *)NULL)->c.seed_ks))
};



/* structure를 return 하는 함수 */
/*	
	Name : SCRT_seed_ctr
	Description: SEED 128 bit CTR 모드 암호알고리즘을 사용하기 위한 정보를 담은 구조체를 반환한다
	Parameters
	Return Value : d_ctr_128_seed 구조체를 반환한다
	Note :
*/
SCRT_CIPHER *SCRT_seed_ctr(void)
{
	return(&d_ctr_128_seed);
}


/*	
	Name : S_seed_ctr_128_init_key
	Description: 암호키 및 카운터를 이용하여 SEED CTR 모드 암호알고리즘에 필요한 키 구조체 및 알고리즘 정보를 설정한다
	Parameters
	[out] ctx : SEED 암/복호화를 위한 SEED_KEY 키 구조체 및 정보를 담은 구조체
	[in] key : 암호키 데이터
	[in] iv : 카운터
	[in] enc : 의미없음
	Return Value : 성공 1 
	Note :
*/
static int S_seed_ctr_128_init_key(SCRT_CIPHER_CTX *ctx, U8 *key, U8 *iv, int enc)
{
	if (iv != NULL)
		memcpy(&(ctx->oiv[0]),iv,16);

	memcpy(&(ctx->iv[0]),&(ctx->oiv[0]),16);  /* iv setting */

	S_SEED_KeySchedule(&(ctx->c.seed_ks),key);

	return 1;
}

/*	
	Name : S_seed_ctr_cipher
	Description: 암호키 및 초기벡터를 이용하여 SEED CTR 모드 암호알고리즘을 이용하여 입력/암호화된 데이터를 암/복호화 한다
	Parameters
	[in] ctx : SEED 암/복호화를 위한 SEED_KEY 키 구조체 및 정보를 담은 구조체
	[out] out : 암/복호화 된 데이터
	[in] in : 암/복호화 할 데이터
	[in] inl : 암/복호화 할 데이터 길이
	Return Value : 
	Note :
*/
static void S_seed_ctr_cipher(SCRT_CIPHER_CTX *ctx, U8 *out, U8 *in, unsigned int inl)
{

	int num = 0;
	U8 ecount_buf[SEED_BLOCK_SIZE];
	memset(ecount_buf, 0 , SEED_BLOCK_SIZE);

	if(ctx->encrypt)
		S_SEED_CTR128_Encrypt(in, out, (long)inl, &(ctx->c.seed_ks), (U8 *)&(ctx->iv), ecount_buf, &num) ;
	else
		S_SEED_CTR128_Decrypt(in, out, (long)inl, &(ctx->c.seed_ks), (U8 *)&(ctx->iv), ecount_buf, &num) ;
}

#endif
