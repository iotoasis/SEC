/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     aes_ctr.c, AES 알고리즘, CTR128 mode

	 Creadted by DEV3

************************************************/
#ifndef AES_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "../include/aes.h"

/*
	Name : S_AES_CTR128_Inc
 	Description : AES CRT 128비트 카운터 증가시킨다. (increment counter (128-bit int) by 1)
 	Parameters
	[in/out] counter : 암호화 카운터 값.
 	Return Value :
 	Note : the IV/counter CTR mode is big-endian.  The rest of the AES code is endian-neutral.
 */
static void S_AES_CTR128_Inc(U8 *counter) 
{
	unsigned long c;

	/* Grab bottom dword of counter and increment */
	c = GETU32(counter + 12);
	c++;	c &= 0xFFFFFFFF;
	PUTU32(counter + 12, c);

	/* if no overflow, we're done */
	if (c)
		return;

	/* Grab 1st dword of counter and increment */
	c = GETU32(counter +  8);
	c++;	c &= 0xFFFFFFFF;
	PUTU32(counter +  8, c);

	/* if no overflow, we're done */
	if (c)
		return;

	/* Grab 2nd dword of counter and increment */
	c = GETU32(counter +  4);
	c++;	c &= 0xFFFFFFFF;
	PUTU32(counter +  4, c);

	/* if no overflow, we're done */
	if (c)
		return;

	/* Grab top dword of counter and increment */
	c = GETU32(counter +  0);
	c++;	c &= 0xFFFFFFFF;
	PUTU32(counter +  0, c);
}

/* The input encrypted as though 128bit counter mode is being
 * used.  The extra state information to record how much of the
 * 128bit block we have used is contained in *num, and the
 * encrypted counter is kept in ecount_buf.  Both *num and
 * ecount_buf must be initialised with zeros before the first
 * call to AES_ctr128_encrypt().
 *
 * This algorithm assumes that the counter is in the x lower bits
 * of the IV (ivec), and that the application has full control over
 * overflow and the rest of the IV.  This implementation takes NO
 * responsability for checking that the counter doesn't overflow
 * into the rest of the IV when incremented.
 */
/*
	Name : S_AES_CTR128_Encrypt
 	Description : CTR 운영모드와 128비트 암호키를 사용하여 평문 데이터를 AES 알고리즘으로 암호화한다.
 	Parameters
 	[in] in : 암호화 대상 데이터
	[out] out : 암호화 결과 데이터
	[in] length : 암호화 대상 데이터 길이
	[in] key : 각 라운드에서 사용할 키 구조체
	[in] ivec : 초기벡터
	[out] ecount_buf : 암호화 Counter 값
	[in/out] num : 128비트 블럭의 여분정보 보관변수
 	Return Value :
 	Note :
 */
void S_AES_CTR128_Encrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 ivec[AES_BLOCK_SIZE], U8 ecount_buf[AES_BLOCK_SIZE], unsigned int *num) 
{

	unsigned int n;
	unsigned long l=length;

	assert(in && out && key && counter && num);
	assert(*num < AES_BLOCK_SIZE);

	n = *num;

	while (l--) {
		if (n == 0) {
			S_AES_Encrypt(ivec, ecount_buf, key);
 			S_AES_CTR128_Inc(ivec);
		}
		*(out++) = *(in++) ^ ecount_buf[n];
		n = (n+1) % AES_BLOCK_SIZE;
	}

	*num=n;
}

/*
	Name : S_AES_CTR128_Decrypt
 	Description : CTR 운영모드와 128비트 암호키를 사용하여 암호화 데이터를 AES 알고리즘으로 복호화 한다.
 	Parameters
 	[in] in : 복호화 대상 암호화 데이터
	[out] out : 복호화된 평문 데이터
	[in] length : 복호화 대상 암호화 데이터 길이
	[in] key : 각 라운드에서 사용할 키 구조체
	[in] ivec : 초기 벡터값
	[out] ecount_buf : 암호화 Counter 값
	[out] num : block size
 	Return Value :
 	Note :
 */
void S_AES_CTR128_Decrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 ivec[AES_BLOCK_SIZE], U8 ecount_buf[AES_BLOCK_SIZE], unsigned int *num) 
{

	unsigned int n;
	unsigned long l=length;

	assert(in && out && key && counter && num);
	assert(*num < AES_BLOCK_SIZE);

	n = *num;

	while (l--) {
		if (n == 0) {
			S_AES_Encrypt(ivec, ecount_buf, key);
 			S_AES_CTR128_Inc(ivec);
		}
		*(out++) = *(in++) ^ ecount_buf[n];
		n = (n+1) % AES_BLOCK_SIZE;
	}

	*num=n;
}