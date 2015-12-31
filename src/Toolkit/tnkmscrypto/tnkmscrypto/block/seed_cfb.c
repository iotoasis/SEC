/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     seed_cfb.c, SEED, CFB 모드

	 Creadted by DEV3

************************************************/

#ifndef NO_SEED

#include "../include/seed.h"
#include "../include/typeconvert.h"

/*	
	Name : S_SEED_CFB_Encrypt
	Description: CFB 운영모드와 128비트 암호키를 사용하여 평문 데이터를 SEED 알고리즘으로 암호화한다.
	Parameters
	[in] in : 암호화 대상 평문 데이터
	[out] out : 암호화 결과값 데이터
	[in] ks : 각 라운드에서 사용할 키 구조체
	[in/out] numbits : 128비트 블럭의 여분정보 보관변수
	[in] bytes : 암호화 대상 평문 데이터 길이값
	[in] iv : 초기 벡터값
	Return Value : 
	Note : 
*/
void S_SEED_CFB_Encrypt(U8 *in, U8 *out, SEED_KEY *ks, int *numbits, long bytes, U8 *iv)
{
	register U32 v0, v1, v2, v3 ;
	register U32 l = bytes;
	register int n = *numbits;
	U32 tin[4];
	U8* ivTmp , c;
	
	ivTmp = (U8*)iv;
	
	while(l--)
	{
		if(n==0)
		{
			U8ToU32(ivTmp, v0); tin[0]=v0;
			U8ToU32(ivTmp, v1); tin[1]=v1;
			U8ToU32(ivTmp, v2); tin[2]=v2;
			U8ToU32(ivTmp, v3); tin[3]=v3;
			S_SEED_Encrypt(tin, ks);
			ivTmp = (U8*)iv;
			v0 = tin[0]; U32ToU8(v0,ivTmp);
			v0 = tin[1]; U32ToU8(v0,ivTmp);
			v0 = tin[2]; U32ToU8(v0,ivTmp);
			v0 = tin[3]; U32ToU8(v0,ivTmp);
			ivTmp = (U8*)iv;
		}
		c= *(in++)^ivTmp[n];
		*(out++)=c;
		ivTmp[n]=c;
		n=(n+1)&0x0f;
	}	
	v0=v1=v2=v3=tin[0]=tin[1]=tin[2]=tin[3]=c=0;
	*numbits = n;
}

/*	
	Name : S_SEED_CFB_Decrypt
	Description: CFB 운영모드와 128비트 암호키를 사용하여 평문 데이터를 SEED 알고리즘으로 복호화한다.
	Parameters
	[in] in : 복호화 대상 암호화 데이터
	[out] out : 복호화 결과값 데이터
	[in] ks : 각 라운드에서 사용할 키 구조체
	[in/out] numbits : 128비트 블럭의 여분정보 보관변수
	[in] bytes : 암호화 데이터 길이값
	[in] iv : 초기 벡터값
	Return Value : 
	Note : 
*/
void S_SEED_CFB_Decrypt(U8 *in, U8 *out, SEED_KEY *ks, int *numbits, long bytes, U8 *iv)
{
	register U32 v0, v1, v2, v3 ;
	register U32 l = bytes;
	register int n = *numbits;
	U32 tin[4];
	U8* ivTmp , c ,cc ;
	
	ivTmp = (U8*)iv;
	
	while(l--)
	{
		if(n==0)
		{
			U8ToU32(ivTmp, v0); tin[0]=v0;
			U8ToU32(ivTmp, v1); tin[1]=v1;
			U8ToU32(ivTmp, v2); tin[2]=v2;
			U8ToU32(ivTmp, v3); tin[3]=v3;
			S_SEED_Encrypt(tin, ks);
			ivTmp = (U8*)iv;
			v0 = tin[0]; U32ToU8(v0,ivTmp);
			v0 = tin[1]; U32ToU8(v0,ivTmp);
			v0 = tin[2]; U32ToU8(v0,ivTmp);
			v0 = tin[3]; U32ToU8(v0,ivTmp);
			ivTmp = (U8*)iv;
		}
		cc=*(in++);
		c=ivTmp[n];
		ivTmp[n]=cc;
		*(out++)=c^cc;
		n=(n+1)&0x0f;
	}
	v0=v1=v2=v3=tin[0]=tin[1]=tin[2]=tin[3]=c=cc=0;
	*numbits = n;
}

/*	
	Name : S_SEED_cfb128_encrypt_ex
	Description: CFB 운영모드와 128비트 암호키를 사용하여 평문 데이터를 SEED 알고리즘으로 암호화한다.
	Parameters
	[in] in : 암호화 대상 평문 데이터
	[out] out : 암호화 결과값 데이터
	[in] len : 암호화 대상 평문 데이터 길이값
	[in] ks : 각 라운드에서 사용할 키 구조체
	[in] ivec : 초기 벡터값
	[in/out] num : 128비트 블럭의 여분정보 보관변수
	Return Value : 
	Note : 
*/
void S_SEED_cfb128_encrypt_ex(const unsigned char *in, unsigned char *out,
                         size_t len, const SEED_KEY *ks,
                         unsigned char ivec[SEED_BLOCK_SIZE], int *num)
{
	int n;

	n = *num;

	while (len--)
	{
		if (n == 0)
			S_SEED_encrypt_ex(ivec, ivec, ks);
		ivec[n] = *(out++) = *(in++) ^ ivec[n];
		n = (n+1) % SEED_BLOCK_SIZE;
	}

	*num = n;
}

/*	
	Name : S_SEED_cfb128_decrypt_ex
	Description: CFB 운영모드와 128비트 암호키를 사용하여 평문 데이터를 SEED 알고리즘으로 복호화한다.
	Parameters
	[in] in : 복호화 대상 암호화 데이터
	[out] out : 복호화 결과값 데이터
	[in] len : 암호화 데이터 길이값
	[in] ks : 각 라운드에서 사용할 키 구조체
	[in] ivec : 초기 벡터값
	[in/out] num : 128비트 블럭의 여분정보 보관변수
	Return Value : 
	Note : 
*/
void S_SEED_cfb128_decrypt_ex(const unsigned char *in, unsigned char *out,
                         size_t len, const SEED_KEY *ks,
                         unsigned char ivec[SEED_BLOCK_SIZE], int *num)
{
	int n;
	unsigned char c;

	n = *num;

	while (len--)
	{
		if (n == 0)
			S_SEED_encrypt_ex(ivec, ivec, ks);
		c = *(in);
		*(out++) = *(in++) ^ ivec[n];
		ivec[n] = c;
		n = (n+1) % SEED_BLOCK_SIZE;
	}

	*num = n;
}

#endif