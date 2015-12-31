/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     aria_cfb.c, ARIA, CFB 모드

	 Creadted by DEV3

************************************************/

#ifndef NO_ARIA

#include <string.h>
#include "../include/aria.h"

/*	
	Name : S_ARIA_CFB128_Encrypt
	Description: 암호키 와 초기벡터를 이용하여 ARIA CFB 모드 암호알고리즘으로 입력 데이터를 암호화 한다
	Parameters
	[in] key : ARIA 키 구조체
	[in] ivec : 초기벡터
	[in] in : 암호화 할 데이터
	[in] inbytes : 암호화 할 데이터 길이
	[out] out : 암호화 된 데이터
	[in] numbits : 128비트 블럭의 여분정보 보관변수

	Return Value : 
	Note : 
*/
void S_ARIA_CFB128_Encrypt(ARIA_KEY *key, U8 *ivec, U8 *in, int inbytes, U8 *out, int *numbits)
{
	U32 n;
	U32 l = inbytes;
	
	n = *numbits;
	
	while (l--) 
	{
		if (n == 0) 
		{
			S_ARIA_Encrypt(key, ivec, ivec);
		}
		
		ivec[n] = *(out++) = *(in++) ^ ivec[n];
		n = (n + 1) % ARIA_BLOCK_SIZE;
	}
	
	*numbits = n;
}

/*	
	Name : S_ARIA_CFB128_Decrypt
	Description: 암호키 와 초기벡터를 이용하여 ARIA CFB 모드 암호알고리즘으로 암호화된 데이터를 복호화 한다
	Parameters
	[in] key : ARIA 키 구조체
	[in] ivec : 초기벡터
	[in] in : 복호화 할 데이터
	[in] inbytes : 복호화 할 데이터 길이
	[out] out : 복호화 된 데이터
	[in] numbits : 128비트 블럭의 여분정보 보관변수
	Return Value : 
	Note : 
*/
void S_ARIA_CFB128_Decrypt(ARIA_KEY *key, U8 *ivec, U8 *in, int inbytes, U8 *out, int *numbits)
{
	U32 n;
	U32 l = inbytes;
	U8 c;
	
	n = *numbits;
	
	while (l--) 
	{
		if (n == 0) 
		{
			S_ARIA_Encrypt(key, ivec, ivec);
		}
		c = *(in);
		*(out++) = *(in++) ^ ivec[n];
		ivec[n] = c;
		n = (n + 1) % ARIA_BLOCK_SIZE;
	}
	
	*numbits = n;
}

#endif