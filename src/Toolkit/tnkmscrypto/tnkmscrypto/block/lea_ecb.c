/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     lea_ecb.c, LEA 알고리즘, ECB 운영모드

	 Creadted by DEV3

************************************************/

#ifndef NO_LEA

#include <stdio.h>
#include "../include/typeconvert.h"
#include "../include/lea.h"

/*	
	Name : S_LEA_ECB_Encrypt
	Description: LEA 알고리즘 ECB모드 암호화 하는 함수
	Parameters
	[in] in : 암호화할 데이터	
	[in] key : 키 구조체
	[in] inbytes : 암호화 대상 평문 데이터 길이값
	[out] out : 암호화된 데이터
	Return Value : 
	Note : 
*/	

int S_LEA_ECB_Encrypt(LEA_KEY *key, const U8 *in, unsigned int in_len, U8 *out)
{
	unsigned int remainBlock = in_len >> 4;

	if (!key){
		return -1;
	}

	if (in_len > 0 && (!in || !out)){
		return -4;
	}

	if (in_len & 0xf){
		return -4;
	}

	for (; remainBlock >= 1; remainBlock -= 1, in += 0x10, out += 0x10)
	{
		S_LEA_Encrypt(key, in, out);
	}

	return 0;
}

/*	
	Name : S_LEA_ECB_Decrypt
	Description: LEA 알고리즘 ECB모드 복호화 하는 함수
	Parameters
	[in] in : 복호화할 암호화 데이터	
	[in] key : 키 구조체
	[in] inbytes : 암호화 대상 평문 데이터 길이값
	[out] out : 복호화된 데이터
	Return Value : 
	Note : 
*/

int S_LEA_ECB_Decrypt(LEA_KEY *key, const U8 *in, unsigned int in_len, U8 *out)
{
	unsigned int remainBlock = in_len >> 4;

	if (!key){
		return -1;
	}

	if (in_len > 0 && (!in || !out)){
		return -4;
	}

	if (in_len & 0xf){
		return -4;
	}

	for (; remainBlock >= 1; remainBlock -= 1, in += 0x10, out += 0x10)
	{
		S_LEA_Decrypt(key, in, out);
	}

	return 0;
}

#endif