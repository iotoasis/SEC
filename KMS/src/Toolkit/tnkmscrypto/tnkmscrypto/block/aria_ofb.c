/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     aria_ofb.c, ARIA, OFB 모드

	 Creadted by DEV3

************************************************/

#ifndef NO_ARIA

#include <string.h>
#include "../include/aria.h"

/*	
	Name : S_ARIA_OFB128_Encrypt
	Description: OFB 운영모드와 128비트 암호키를 사용하여 평문 데이터를 ARIA 알고리즘으로 암호화한다.
	Parameters
	[in] key : 각 라운드에서 사용할 키 구조체
	[in] iv : 초기 벡터값
	[in] in : 암호화 대상 평문 데이터
	[in] inbytes : 암호화 대상 평문 데이터 길이값
	[out] out : 암호화 결과값 데이터
	[in/out] numbits : 128비트 블럭의 여분정보 보관변수
	Return Value : 
	Note : 
*/
void S_ARIA_OFB128_Encrypt(ARIA_KEY *key, U8 *iv, U8 *in, unsigned int inbytes, U8 *out, int *numbits)
{
	unsigned int n;
	unsigned int l=inbytes;
	
	n = *numbits;

	while (l--) 
	{
		if (n == 0) 
		{
			S_ARIA_Encrypt(key, (U8 *)iv, (U8 *)iv);
		}
		*(out++) = *(in++) ^ iv[n];
		n = (n+1) % ARIA_BLOCK_SIZE;
	}
	
	*numbits=n;
}

/*	
	Name : S_ARIA_OFB128_Decrypt
	Description: OFB 운영모드와 128비트 암호키를 사용하여 평문 데이터를 ARIA 알고리즘으로 복호화한다.
	Parameters
	[in] key : 각 라운드에서 사용할 키 구조체
	[in] iv : 초기 벡터값
	[in] in : 복호화 대상 암호화 데이터
	[in] inbytes : 복호화 대상 암호화 데이터 길이값
	[out] out : 복호화된 평문 데이터
	[in/out] numbits : 128비트 블럭의 여분정보 보관변수
	Return Value : 
	Note : 
*/
void S_ARIA_OFB128_Decrypt(ARIA_KEY *key, U8 *iv, U8 *in, unsigned int inbytes, U8 *out, int *numbits)
{
	S_ARIA_OFB128_Encrypt(key, iv, in, inbytes, out, numbits);
}

#endif