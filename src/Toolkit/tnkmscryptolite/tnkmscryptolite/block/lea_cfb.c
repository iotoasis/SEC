/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     lea_cfb.c, LEA 알고리즘, CFB128 운영모드

	 Creadted by DEV3

************************************************/

#ifndef NO_LEA

#include <stdio.h>
#include "../include/typeconvert.h"
#include "../include/lea.h"

/*	
	Name : S_LEA_CFB128_Encrypt
	Description: 암호키 와 초기벡터를 이용하여 LEA CFB128 모드 암호알고리즘으로 입력 데이터를 암호화 한다
	Parameters
	[in] key : LEA 키 구조체
	[in] ivec : 초기벡터
	[in] in : 암호화 할 데이터
	[in] in_len : 암호화 할 데이터 길이
	[out] out : 암호화 된 데이터
	Return Value : 
	Note : 
*/
int S_LEA_CFB128_Encrypt(LEA_KEY *key, U8 *ivec, const U8 *in, unsigned int in_len, U8 *out)
{
	const unsigned char *pIv = ivec;
	unsigned char block[16];
	unsigned int nBlock1 = in_len >> 4, i=0;

	if (!key){
		return -1;
	}

	if (!ivec){
		return -3;
	}

	if (in_len > 0 && (!in||!out)){
		return -4;
	}

	for(i = 0; i < nBlock1; i++, in += 0x10, out += 0x10)
	{
		S_LEA_Encrypt(key, pIv, block);
		XOR8x16(out, block, in);

		pIv = out;
	}

	if (in_len & 0xf){
		S_LEA_Encrypt(key, pIv, block);

		for (i = 0; i < (in_len & 0xf); i++)
		{
			out[i] = block[i] ^ in[i];
		}
	}

	return 0;
}

/*	
	Name : S_LEA_CFB128_Decrypt
	Description: 암호키 와 초기벡터를 이용하여 LEA CFB128 모드 암호알고리즘으로 암호화된 데이터를 복호화 한다
	Parameters
	[in] key : LEA 키 구조체
	[in] ivec : 초기벡터
	[in] in : 복호화 할 데이터
	[in] in_len : 복호화 할 데이터 길이
	[out] out : 복호화 된 데이터
	Return Value : 
	Note : 
*/
int S_LEA_CFB128_Decrypt(LEA_KEY *key, U8 *ivec, const U8 *in, unsigned int in_len, U8 *out)
{
	U32 n = 0;
	U32 l = in_len;
	U8 c;
	
	if (!key){
		return -1;
	}

	if (!ivec){
		return -3;
	}

	if (in_len > 0 && (!in||!out)){
		return -4;
	}
	
	while (l--) 
	{
		if (n == 0) 
		{
			S_LEA_Encrypt(key, ivec, ivec);
		}
		c = *(in);
		*(out++) = *(in++) ^ ivec[n];
		ivec[n] = c;
		n = (n + 1) % LEA_BLOCK_SIZE;
	}

	return 0;
}


#endif