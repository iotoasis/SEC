/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     aria_ecb.c, ARIA, ECB 모드

	 Creadted by DEV3

************************************************/

#ifndef NO_ARIA

#include <string.h>
#include "../include/aria.h"

/*	
	Name : S_ARIA_ECB_Encrypt
	Description: ARIA 알고리즘 ECB모드 암호화 하는 함수
	Parameters
	[in] in : 암호화할 데이터	
	[in] key : 키 구조체
	[in] inbytes : 암호화 대상 평문 데이터 길이값
	[out] out : 암호화된 데이터
	Return Value : 
	Note : 
*/	
void S_ARIA_ECB_Encrypt(ARIA_KEY *key, U8 *in, int inbytes, U8 *out)
{
	U32 len = inbytes;
	
	while (len >= ARIA_BLOCK_SIZE) 
	{
		S_ARIA_Encrypt(key, in, out);
		len -= ARIA_BLOCK_SIZE;
		in += ARIA_BLOCK_SIZE;
		out += ARIA_BLOCK_SIZE;
	}
	
	if (len) 
	{
		S_ARIA_Encrypt(key, in, out);
	}
}
/*	
	Name : S_ARIA_ECB_Decrypt
	Description: ARIA 알고리즘 ECB모드 복호화 하는 함수
	Parameters
	[in] in : 복호화할 암호화 데이터	
	[in] key : 키 구조체
	[in] inbytes : 암호화 대상 평문 데이터 길이값
	[out] out : 복호화된 데이터
	Return Value : 
	Note : 
*/
void S_ARIA_ECB_Decrypt(ARIA_KEY *key, U8 *in, int inbytes, U8 *out)
{
	U32 len = inbytes;
	
	while (len >= ARIA_BLOCK_SIZE) 
	{
		S_ARIA_Decrypt(key, in, out);
		len -= ARIA_BLOCK_SIZE;
		in += ARIA_BLOCK_SIZE;
		out += ARIA_BLOCK_SIZE;
	}
	
	if (len) 
	{
		S_ARIA_Decrypt(key, in, out);
	}
}

#endif
