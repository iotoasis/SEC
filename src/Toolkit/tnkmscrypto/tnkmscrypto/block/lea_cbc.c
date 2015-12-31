/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     lea_cbc.c, LEA 알고리즘, CBC운영모드

	 Creadted by DEV3

************************************************/

#ifndef NO_LEA

#include <stdio.h>
#include "../include/typeconvert.h"
#include "../include/lea.h"

/*	
	Name : S_LEA_CBC_Encrypt
	Description: 암호키 와 초기벡터를 이용하여 LEA CBC 모드 암호알고리즘으로 입력 데이터를 암호화 한다
	Parameters
	[in] key : LEA 키 구조체
	[in] ivec : 초기벡터
	[in] in : 암호화 할 데이터
	[in] in_len : 암호화 할 데이터 길이
	[out] out : 암호화 된 데이터
	Return Value :
	Note : 
*/
int S_LEA_CBC_Encrypt(LEA_KEY *key, U8 *ivec, const U8 *in, unsigned int in_len, U8 *out)
{
	unsigned int nBlock1 = in_len >> 4, i=0;
	const unsigned char *iv_ptr = ivec;

	if (out == NULL)
		return -5;
	else if (in == NULL)
		return -4;
	else if ((in_len == 0) || (in_len & 0xf))
		return -4;
	else if (ivec == NULL)
		return -3;
	else if (key == NULL)
		return -1;

	for(i = 0; i < nBlock1; i++, in += 16, out += 16)
	{
		XOR8x16(out, in, iv_ptr);
		S_LEA_Encrypt(key, out, out);

		iv_ptr = out;
	}

	return 0;
}

/*	
	Name : S_LEA_CBC_Decrypt
	Description: 암호키 와 초기벡터를 이용하여 LEA CBC 모드 암호알고리즘으로 암호화된 데이터를 복호화 한다
	Parameters
	[in] key : LEA 키 구조체
	[in] ivec : 초기벡터
	[in] in : 복호화 할 데이터
	[in] in_len : 복호화 할 데이터 길이
	[out] out : 복호화 된 데이터
	Return Value :
	Note : 
*/
int S_LEA_CBC_Decrypt(LEA_KEY *key, U8 *ivec, const U8 *in, unsigned int in_len, U8 *out)
{
	unsigned int remainBlock = in_len >> 4;
	const unsigned char *pIv = ivec;

	if (out == NULL)
		return;
	else if (in == NULL)
		return;
	else if ((in_len == 0) || (in_len & 0xf))
		return;
	else if (ivec == NULL)
		return;
	else if (key == NULL)
		return;

	out += in_len;
	in += in_len;

	while (remainBlock > 1){ // > 1, not >= 1.
		out -= 0x10;
		in -= 0x10;
		pIv = in - 16;

		S_LEA_Decrypt(key, in, out);

		XOR8x16(out, out, pIv);

		remainBlock -= 1;
	}
	
	out -= 0x10;
	in -= 0x10;

	S_LEA_Decrypt(key, in, out);

	XOR8x16(out, out, ivec);

}


#endif