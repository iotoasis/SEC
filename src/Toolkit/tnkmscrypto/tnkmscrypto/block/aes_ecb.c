/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     aes_ecb.c, AES 알고리즘, ECB mode

	 Creadted by DEV3

************************************************/
#ifndef AES_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif
#include <assert.h>

#include "../include/aes.h"
/*	
	Name : S_AES_ECB_Encrypt
	Description: AES 알고리즘 ECB모드 암호화 하는 함수
	Parameters
	[in] in : 암호화할 데이터
	[out] out : 암호화된 데이터
	[in] key : 키 구조체
	Return Value : 128bit ECB mode 암호화
	Note : 
*/	
void S_AES_ECB_Encrypt(U8 *in, U8 *out, AES_KEY_ST *key) 
{

    assert(in && out && key);

	S_AES_Encrypt(in, out, key);
}
/*	
	Name : S_AES_ECB_Decrypt
	Description: AES 알고리즘 ECB모드 복호화 하는 함수
	Parameters
	[in] in : 복호화할 암호화 데이터
	[out] out : 복호화된 데이터
	[in] key : 키 구조체
	Return Value : 128bit ECB mode 복호화
	Note : 
*/	
void S_AES_ECB_Decrypt(U8 *in, U8 *out, AES_KEY_ST *key) 
{

    assert(in && out && key);

	S_AES_Decrypt(in, out, key);
}