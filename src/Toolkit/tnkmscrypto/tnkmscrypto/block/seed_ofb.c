/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     seed_ofb.c, SEED, OFB 모드

	 Creadted by DEV3

************************************************/

#ifndef NO_SEED

#include "../include/seed.h"
#include "../include/typeconvert.h"

typedef unsigned char seed_cblock[16];

/* 64bit OFB 모드 */
/*	
	Name : S_SEED_OFB_Encrypt
	Description: 암호키를 이용하여 SEED OFB 모드 암호알고리즘으로 입력 데이터를 암호화 한다
	Parameters
	[in] in : 암호화 할 데이터
	[out] out : 암호화 된 데이터
	[in] ks : SEED 키 구조체
	[in] numbits : 128비트 블럭의 여분정보 보관변수
	[in] bytes : 암호화 할 데이터 길이
	[in] iv : 초기벡터
	Return Value : 
	Note : 
*/
void S_SEED_OFB_Encrypt(U8 *in, U8 *out, SEED_KEY *ks, int  *numbits, long bytes,  U8 *iv)
{
	register U32 v0,v1,v2,v3,t;
	register int n= *numbits;
	register long l= bytes;
	seed_cblock d; 
	register U8 *dp;
	U32 tin[4];
	U8 *ivTmp;
	int save=0;

	ivTmp = (U8 *)iv;
	U8ToU32(ivTmp,v0);
	U8ToU32(ivTmp,v1);
	U8ToU32(ivTmp,v2);
	U8ToU32(ivTmp,v3);
	tin[0]=v0;
	tin[1]=v1;
	tin[2]=v2;
	tin[3]=v3;
	dp=d;
	U32ToU8(v0,dp);
	U32ToU8(v1,dp);
	U32ToU8(v2,dp);
	U32ToU8(v3,dp);
	while (l--)
		{
		if (n == 0)
			{
			S_SEED_Encrypt(tin,ks);
			dp=d;
			t=tin[0]; U32ToU8(t,dp);
			t=tin[1]; U32ToU8(t,dp);
			t=tin[2]; U32ToU8(t,dp);
			t=tin[3]; U32ToU8(t,dp);
			save++;
			}
		*(out++)= *(in++)^d[n];
		n=(n+1)&0x0f;
		}
	if (save)
		{
		v0=tin[0];
		v1=tin[1];
		v2=tin[2];
		v3=tin[3];
		ivTmp = (U8 *)iv;
		U32ToU8(v0,ivTmp);
		U32ToU8(v1,ivTmp);
		U32ToU8(v2,ivTmp);
		U32ToU8(v3,ivTmp);
		}
	t=v0=v1=v2=v3=tin[0]=tin[1]=tin[2]=tin[3]=0;
	*numbits=n;
}

/*	
	Name : S_SEED_OFB_Decrypt
	Description: 암호키를 이용하여 SEED OFB 모드 암호알고리즘으로 암호화된 데이터를 복호화 한다
	Parameters
	[in] in : 복호화 할 데이터
	[out] out : 복호화 된 데이터
	[in] ks : SEED 키 구조체
	[in] numbits : 128비트 블럭의 여분정보 보관변수
	[in] bytes : 복호화 할 데이터 길이
	[in] iv : 초기벡터
	Return Value : 
	Note : 
*/
void S_SEED_OFB_Decrypt(U8 *in, U8 *out, SEED_KEY *ks, int  *numbits, long bytes,  U8 *iv)
{
	S_SEED_OFB_Encrypt(in, out, ks, numbits, bytes,  iv);	
}

#endif