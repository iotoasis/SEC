/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     lea_ofb.c, LEA 알고리즘, OFB128 운영모드

	 Creadted by DEV3

************************************************/

#ifndef NO_LEA

#include <stdio.h>
#include "../include/typeconvert.h"
#include "../include/lea.h"

/*	
	Name : S_LEA_OFB128_Encrypt
	Description: OFB 운영모드와 128비트 암호키를 사용하여 평문 데이터를 LEA 알고리즘으로 암호화한다.
	Parameters
	[in] key : 각 라운드에서 사용할 키 구조체
	[in] iv : 초기 벡터값
	[in] in : 암호화 대상 평문 데이터
	[in] in_len : 암호화 대상 평문 데이터 길이값
	[out] out : 암호화 결과값 데이터
	Return Value : 
	Note : 
*/
int S_LEA_OFB128_Encrypt(LEA_KEY *key, U8 *ivec, const U8 *in, unsigned int in_len, U8 *out)
{
	unsigned int numBlock1 = in_len >> 4, i=0;

	if (!key){
		return -1;
	}

	if (!ivec){
		return -3;
	}

	if (in_len > 0 && (!out || !in)){
		return -4;
	}

	for(i = 0; i < numBlock1; i++, in += 0x10, out += 0x10)
	{
		S_LEA_Encrypt(key, ivec, ivec);

		XOR8x16(out, in, ivec);
	}

	if((numBlock1 << 4) != in_len)
	{
		S_LEA_Encrypt(key, ivec, ivec);

		for(i = 0; i < in_len - (numBlock1 << 4); i++)
			out[i] = ivec[i] ^ in[i];
	}

	return 0;
}

/*	
	Name : S_LEA_OFB128_Decrypt
	Description: OFB 운영모드와 128비트 암호키를 사용하여 평문 데이터를 LEA 알고리즘으로 복호화한다.
	Parameters
	[in] key : 각 라운드에서 사용할 키 구조체
	[in] iv : 초기 벡터값
	[in] in : 복호화 대상 암호화 데이터
	[in] in_len : 복호화 대상 암호화 데이터 길이값
	[out] out : 복호화된 평문 데이터
	Return Value : 
	Note : 
*/
int S_LEA_OFB128_Decrypt(LEA_KEY *key, U8 *ivec, const U8 *in, unsigned int in_len, U8 *out)
{
	int ret;
	ret = S_LEA_OFB128_Encrypt(key, ivec, in, in_len, out);

	return ret;
}
#endif