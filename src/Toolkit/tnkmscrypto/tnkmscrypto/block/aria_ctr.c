/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     aria_ctr.c, ARIA, CTR 모드

	 Creadted by DEV3

************************************************/

#ifndef NO_ARIA

#include <string.h>
#include <stdlib.h>
#include "../include/aria.h"
 
#if defined(_MSC_VER) && !defined(_M_IA64)
# define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
# define GETU32(p) SWAP(*((U32 *)(p)))
# define PUTU32(ct, st) { *((U32 *)(ct)) = SWAP((st)); }
#else
# define GETU32(pt) (((U32)(pt)[0] << 24) ^ ((U32)(pt)[1] << 16) ^ ((U32)(pt)[2] <<  8) ^ ((U32)(pt)[3]))
# define PUTU32(ct, st) { (ct)[0] = (U8)((st) >> 24); (ct)[1] = (U8)((st) >> 16); (ct)[2] = (U8)((st) >>  8); (ct)[3] = (U8)(st); }
#endif


/*
	Name : S_ARIA_CTR128_Inc
 	Description : ARIA CRT 128비트 카운터를 증가시킨다.  (increment counter (128-bit int) by 1)
 	Parameters 	
	[in/out] counter : 암호화 카운터 값.
 	Return Value :
 	Note : the IV/counter CTR mode is big-endian.  The rest of the AES code is endian-neutral.
 */
static void S_ARIA_CTR128_Inc(U8 *counter) 
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
	Name : S_ARIA_CTR128_Encrypt
 	Description : CTR 운영모드와 128비트 암호키를 사용하여 평문 데이터를 ARIA 알고리즘으로 암호화한다.
 	Parameters
 	[in] key : 암호화 키값
	[in] iv : 초기벡터
	[in] in : 암호화 대상 데이터
	[in] inbytes : 암호화 대상 데이터 크기
	[out] out : 암호화 결과 데이터
	[in] ecount_buf : 암호화 counter 값
	[in/out] numbits : 블럭의 여분정보 보관변수
 	Return Value :
 	Note :
 */
void S_ARIA_CTR128_Encrypt(ARIA_KEY *key, U8 *iv, U8 *in, unsigned int inbytes, U8 *out, U8 *ecount_buf, int *numbits) 
{
	
	unsigned int n;
	unsigned int l=inbytes;
		
	n = *numbits;
	
	while (l--) {
		if (n == 0) {
			S_ARIA_Encrypt(key, (U8 *)iv, (U8 *)ecount_buf);
			S_ARIA_CTR128_Inc(iv);
		}
		*(out++) = *(in++) ^ ecount_buf[n];
		n = (n+1) % 16;
	}
	
	*numbits=n;
}

/*
	Name : S_ARIA_CTR128_Decrypt
 	Description : CTR 운영모드와 128비트 암호키를 사용하여 평문 데이터를 ARIA 알고리즘으로 복호화한다.
 	Parameters
 	[in] key : 복호화 키값
	[in] iv : 초기벡터
	[in] in : 암호화 된 데이터
	[in] inbytes : 암호화 된 데이터 크기
	[out] out : 복호 결과 데이터
	[in] ecount_buf : 암호화 counter 값
	[in/out] numbits : 블럭의 여분정보 보관변수
 	Return Value :
 	Note :
 */
void S_ARIA_CTR128_Decrypt(ARIA_KEY *key, U8 *iv, U8 *in, unsigned int inbytes, U8 *out, U8 *ecount_buf, int *numbits) 
{
	
	unsigned int n;
	unsigned int l=inbytes;
	
	n = *numbits;
	
	while (l--) {
		if (n == 0) {
			S_ARIA_Encrypt(key, (U8 *)iv, (U8 *)ecount_buf);
			S_ARIA_CTR128_Inc(iv);
		}
		*(out++) = *(in++) ^ ecount_buf[n];
		n = (n+1) % /* AES_BLOCK_SIZE */ 16;
	}
	
	*numbits=n;
}

#endif
