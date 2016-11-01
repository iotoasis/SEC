/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     aria_cbc.c, ARIA, CBC 모드

	 Creadted by DEV3

************************************************/

#ifndef NO_ARIA

#include <string.h>
#include "../include/aria.h"

/*	
	Name : S_ARIA_CBC_Encrypt
	Description: 암호키 와 초기벡터를 이용하여 ARIA CBC 모드 암호알고리즘으로 입력 데이터를 암호화 한다
	Parameters
	[in] key : ARIA 키 구조체
	[in] ivec : 초기벡터
	[in] in : 암호화 할 데이터
	[in] inbytes : 암호화 할 데이터 길이
	[out] out : 암호화 된 데이터
	Return Value :
	Note : 
*/
void S_ARIA_CBC_Encrypt(ARIA_KEY *key, U8 *ivec, U8 *in, int inbytes, U8 *out)
{
	U32 n;
	U32 len = inbytes;
	const U8 *iv = ivec;
	
	while (len >= ARIA_BLOCK_SIZE) 
	{
		for (n = 0; n < ARIA_BLOCK_SIZE; ++n)
			out[n] = in[n] ^ iv[n];
		S_ARIA_Encrypt(key, out, out);
		iv = out;
		len -= ARIA_BLOCK_SIZE;
		in += ARIA_BLOCK_SIZE;
		out += ARIA_BLOCK_SIZE;
	}
	
	if (len) 
	{
		for (n = 0; n < len; ++n)
			out[n] = in[n] ^ iv[n];
		for (n = len; n < ARIA_BLOCK_SIZE; ++n)
			out[n] = iv[n];
		S_ARIA_Encrypt(key, out, out);
		iv = out;
	}

	memcpy(ivec, iv, ARIA_BLOCK_SIZE);
}

/*	
	Name : S_ARIA_CBC_Decrypt
	Description: 암호키 와 초기벡터를 이용하여 ARIA CBC 모드 암호알고리즘으로 암호화된 데이터를 복호화 한다
	Parameters
	[in] key : ARIA 키 구조체
	[in] ivec : 초기벡터
	[in] in : 복호화 할 데이터
	[in] inbytes : 복호화 할 데이터 길이
	[out] out : 복호화 된 데이터
	Return Value :
	Note : 
*/
void S_ARIA_CBC_Decrypt(ARIA_KEY *key, U8 *ivec, U8 *in, int inbytes, U8 *out)
{
	U32 n;
	U32 len = inbytes;
	U8 tmp[ARIA_BLOCK_SIZE];
	const U8 *iv = ivec;
	
	if (in != out) 
	{
		while (len >= ARIA_BLOCK_SIZE) 
		{
			S_ARIA_Decrypt(key, in, out);
			for (n = 0; n < ARIA_BLOCK_SIZE; ++n)
				out[n] ^= iv[n];
			iv = in;
			len -= ARIA_BLOCK_SIZE;
			in  += ARIA_BLOCK_SIZE;
			out += ARIA_BLOCK_SIZE;
		}

		if (len) 
		{
			S_ARIA_Decrypt(key, in, tmp);
			for (n = 0; n < len; ++n)
				out[n] = tmp[n] ^ iv[n];
			iv = in;
		}

		memcpy(ivec, iv, ARIA_BLOCK_SIZE);
	}
	else 
	{
		while (len >= ARIA_BLOCK_SIZE) 
		{
			memcpy(tmp, in, ARIA_BLOCK_SIZE);
			S_ARIA_Decrypt(key, in, out);
			for(n=0; n < ARIA_BLOCK_SIZE; ++n)
				out[n] ^= ivec[n];
			memcpy(ivec, tmp, ARIA_BLOCK_SIZE);
			len -= ARIA_BLOCK_SIZE;
			in += ARIA_BLOCK_SIZE;
			out += ARIA_BLOCK_SIZE;
		}

		if (len) 
		{
			memcpy(tmp, in, ARIA_BLOCK_SIZE);
			S_ARIA_Decrypt(key, tmp, out);
			for (n = 0; n < len; ++n)
				out[n] ^= ivec[n];
			for (n = len; n < ARIA_BLOCK_SIZE; ++n)
				out[n] = tmp[n];
			memcpy(ivec, tmp, ARIA_BLOCK_SIZE);
		}
	}
}

#endif