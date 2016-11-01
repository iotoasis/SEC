/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     aes_ofb.c, AES 알고리즘, OFB128 mode

	 Creadted by DEV3

************************************************/
#ifndef AES_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif
#include <assert.h>
#include "../include/aes.h"

/* The input and output encrypted as though 128bit ofb mode is being
 * used.  The extra state information to record how much of the
 * 128bit block we have used is contained in *num;
 */
/*	
	Name : S_AES_OFB128_Encrypt
	Description: OFB 운영모드와 128비트 암호키를 사용하여 평문 데이터를 AES 알고리즘으로 암호화한다.
	Parameters
	[in] in : 암호화 대상 평문 데이터
	[out] out : 암호화 결과값 데이터
	[in] length : 암호화 대상 평문 데이터 길이값
	[in] key : 각 라운드에서 사용할 키 구조체
	[in] ivec : 초기 벡터값
	[in/out] num : 128비트 블럭의 여분정보 보관변수
	Return Value : 
	Note : 
*/
void S_AES_OFB128_Encrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec, unsigned int *num) 
{
	unsigned int n;
	unsigned long l=length;

	assert(in && out && key && ivec && num);

	n = *num;

	while (l--) {
		if (n == 0) {
			S_AES_Encrypt(ivec, ivec, key);
		}
		*(out++) = *(in++) ^ ivec[n];
		n = (n+1) % AES_BLOCK_SIZE;
	}

	*num=n;
}

/*	
	Name : S_AES_OFB128_Decrypt
	Description: OFB 운영모드와 128비트 암호키를 사용하여 암호화 데이터를 AES 알고리즘으로 복호화한다.
	Parameters
	[in] in : 복호화 대상 암호화 데이터
	[out] out : 복호화된 평문 데이터
	[in] length : 복호화 대상 암호화 데이터 길이값
	[in] key : 각 라운드에서 사용할 키 구조체
	[in] ivec : 초기 벡터값
	[in/out] num : 128비트 블럭의 여분정보 보관변수
	Return Value : 
	Note : 
*/
void S_AES_OFB128_Decrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec, unsigned int *num) 
{
	unsigned int n;
	unsigned long l=length;

	assert(in && out && key && ivec && num);

	n = *num;

	while (l--) {
		if (n == 0) {
			S_AES_Encrypt(ivec, ivec, key);
		}
		*(out++) = *(in++) ^ ivec[n];
		n = (n+1) % AES_BLOCK_SIZE;
	}

	*num=n;
}
