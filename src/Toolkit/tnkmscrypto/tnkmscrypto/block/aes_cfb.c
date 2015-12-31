/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     aes_cfb.c, AES 알고리즘, CFB128 mode

	 Creadted by DEV3

************************************************/
#ifndef AES_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif
#include <assert.h>
#include <string.h>
#include "../include/aes.h"

/* The input and output encrypted as though 128bit cfb mode is being
 * used.  The extra state information to record how much of the
 * 128bit block we have used is contained in *num;
 */

 /*	
	Name : S_AES_CFB128_Encrypt
	Description: 암호키 와 초기벡터를 이용하여 AES CFB 모드 암호알고리즘으로 입력 데이터를 암호화 한다
	Parameters
	[in] in : 암호화 할 데이터
	[out] out : 암호화 된 데이터
	[in] length : 암호화할 데이터의 길이
	[in] key : 키 구조체
	[in] ivec : 초기벡터
	[in/out] num : 128비트 블럭의 여분정보 보관변수
	Return Value :  
	Note : 128bit cfb mode 암호화
*/
void S_AES_CFB128_Encrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec, unsigned int *num) 
{

	unsigned int n;
	unsigned long l = length;

	assert(in && out && key && ivec && num);

	n = *num;

	while (l--) 
	{
		if (n == 0) 
		{
			S_AES_Encrypt(ivec, ivec, key);
		}

		ivec[n] = *(out++) = *(in++) ^ ivec[n];
		n = (n+1) % AES_BLOCK_SIZE;
	}

	*num=n;
}

/*	
	Name : S_AES_CFB128_Decrypt
	Description: 암호키 와 초기벡터를 이용하여 AES CFB 모드 암호알고리즘으로 입력 데이터를 복호화 한다
	Parameters
	[in] in : 복호화 할 데이터
	[out] out : 복호화 된 데이터
	[in] length : 복호화할 데이터의 길이
	[in] key : 키 구조체
	[in] ivec : 초기벡터
	[in/out] num : 128비트 블럭의 여분정보 보관변수
	Return Value :  
	Note : 128bit cfb mode 복호화
*/
void S_AES_CFB128_Decrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec, unsigned int *num) 
{

	unsigned int n;
	unsigned long l = length;
	unsigned char c;

	assert(in && out && key && ivec && num);

	n = *num;

	while (l--) 
	{
		if (n == 0) 
		{
			S_AES_Encrypt(ivec, ivec, key);
		}
		c = *(in);
		*(out++) = *(in++) ^ ivec[n];
		ivec[n] = c;
		n = (n+1) % AES_BLOCK_SIZE;
	}

	*num=n;
}

/* This expects a single block of size nbits for both in and out. Note that
   it corrupts any extra bits in the last byte of out */
/*	
	Name : S_AES_CFBR_Encrypt_Block
	Description: 암호키 와 초기벡터를 이용하여 AES CFB 모드 암호알고리즘으로 입력 데이터를 암호화 한다
	Parameters
	[in] in : 암호화 할 데이터
	[out] out : 암호화 된 데이터
	[in] nbits : 여분정보 보관변수
	[in] key : 키 구조체
	[in] ivec : 초기벡터
	Return Value : 
	Note : 
*/   
void S_AES_CFBR_Encrypt_Block(U8 *in, U8 *out, int nbits, AES_KEY_ST *key, U8 *ivec)
{
    int n,rem,num;
    U8 ovec[AES_BLOCK_SIZE*2];//unsigned char ovec[AES_BLOCK_SIZE*2]; dgshin-1204

    if (nbits<=0 || nbits>128) return;

	/* fill in the first half of the new IV with the current IV */
	memcpy(ovec,ivec,AES_BLOCK_SIZE);
	/* construct the new IV */
	S_AES_Encrypt(ivec,ivec,key);
	num = (nbits+7)/8;

	/* encrypt the input */
	for(n=0 ; n < num ; ++n)
		out[n] = (ovec[AES_BLOCK_SIZE+n] = in[n] ^ ivec[n]);

	/* shift ovec left... */
	rem = nbits%8;
	num = nbits/8;
	if(rem==0)
	    memcpy(ivec,ovec+num,AES_BLOCK_SIZE);
	else
	    for(n=0 ; n < AES_BLOCK_SIZE ; ++n)
		ivec[n] = ovec[n+num]<<rem | ovec[n+num+1]>>(8-rem);

    /* it is not necessary to cleanse ovec, since the IV is not secret */
}

/*	
	Name : S_AES_CFBR_Decrypt_Block
	Description: 암호키 와 초기벡터를 이용하여 AES CFB 모드 암호알고리즘으로 입력 데이터를 복호화 한다
	Parameters
	[in] in : 복호화 할 데이터
	[out] out : 복호화 된 데이터
	[in] nbits : 여분정보 보관변수
	[in] key : 키 구조체
	[in] ivec : 초기벡터
	Return Value : 
	Note : 
*/
void S_AES_CFBR_Decrypt_Block(U8 *in, U8 *out, int nbits, AES_KEY_ST *key, U8 *ivec)
{
    int n,rem,num;
    U8 ovec[AES_BLOCK_SIZE*2];//unsigned char ovec[AES_BLOCK_SIZE*2]; dgshin-1204

    if (nbits<=0 || nbits>128) return;

	/* fill in the first half of the new IV with the current IV */
	memcpy(ovec,ivec,AES_BLOCK_SIZE);
	/* construct the new IV */
	S_AES_Encrypt(ivec,ivec,key);
	num = (nbits+7)/8;

	/* decrypt the input */
	for(n=0 ; n < num ; ++n)
		out[n] = (ovec[AES_BLOCK_SIZE+n] = in[n]) ^ ivec[n];

	/* shift ovec left... */
	rem = nbits%8;
	num = nbits/8;
	if(rem==0)
	    memcpy(ivec,ovec+num,AES_BLOCK_SIZE);
	else
	    for(n=0 ; n < AES_BLOCK_SIZE ; ++n)
		ivec[n] = ovec[n+num]<<rem | ovec[n+num+1]>>(8-rem);

    /* it is not necessary to cleanse ovec, since the IV is not secret */
}

/* N.B. This expects the input to be packed, MS bit first */
/*	
	Name : S_AES_CFB1_Encrypt
	Description: 암호키 와 초기벡터를 이용하여 AES CFB 모드 암호알고리즘으로 입력 데이터를 암호화 한다
	Parameters
	[in] in : 암호화 할 데이터
	[out] out : 암호화 된 데이터
	[in] length : 원문의 길이
	[in] key : 키 구조체
	[in] ivec : 초기벡터
	[in] num : 여분정보 보관변수

	Return Value : 
	Note : 
*/
void S_AES_CFB1_Encrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec, unsigned int *num)
{
    unsigned int n;
    U8 c[1],d[1];//unsigned char c[1],d[1]; dgshin-1204

    assert(in && out && key && ivec && num);
    assert(*num == 0);

    memset(out,0,(length+7)/8);
    for(n=0 ; n < length ; ++n)
	{
		c[0]=(in[n/8]&(1 << (7-n%8))) ? 0x80 : 0;
		S_AES_CFBR_Encrypt_Block(c,d,1,key,ivec);
		out[n/8]=(out[n/8]&~(1 << (7-n%8)))|((d[0]&0x80) >> (n%8));
	}
}

/*	
	Name : S_AES_CFB1_Decrypt
	Description: 암호키 와 초기벡터를 이용하여 AES CFB 모드 암호알고리즘으로 입력 데이터를 복호화 한다
	Parameters
	[in] in : 복호화 할 데이터
	[out] out : 복호화 할 데이터
	[in] length : 원문의 길이
	[in] key : 키 구조체
	[in] ivec : 초기벡터
	[in] num : 여분정보 보관변수
	Return Value : 
	Note : 
*/
void S_AES_CFB1_Decrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec, unsigned int *num)
{
    unsigned int n;
    U8 c[1],d[1];//unsigned char c[1],d[1]; dgshin-1204

    assert(in && out && key && ivec && num);
    assert(*num == 0);

    memset(out,0,(length+7)/8);
    for(n=0 ; n < length ; ++n)
	{
		c[0]=(in[n/8]&(1 << (7-n%8))) ? 0x80 : 0;
		S_AES_CFBR_Decrypt_Block(c,d,1,key,ivec);
		out[n/8]=(out[n/8]&~(1 << (7-n%8)))|((d[0]&0x80) >> (n%8));
	}
}

/*	
	Name : S_AES_CFB8_Encrypt
	Description: 암호키 와 초기벡터를 이용하여 AES CFB 모드 암호알고리즘으로 입력 데이터를 암호화 한다
	Parameters
	[in] in : 암호화 할 데이터
	[out] out : 암호화 할 데이터
	[in] length : 원문의 길이
	[in] key : 키 구조체
	[in] ivec : 초기벡터
	[in] num : 의미없음
	Return Value : 
	Note : 
*/
void S_AES_CFB8_Encrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec, unsigned int *num)
{
    unsigned int n;

    assert(in && out && key && ivec && num);
    assert(*num == 0);

    for(n=0 ; n < length ; ++n)
	S_AES_CFBR_Encrypt_Block(&in[n],&out[n],8,key,ivec);
}

/*	
	Name : S_AES_CFB8_Decrypt
	Description: 암호키 와 초기벡터를 이용하여 AES CFB 모드 암호알고리즘으로 입력 데이터를 복호화 한다
	Parameters
	[in] in : 암호화 할 데이터
	[out] out : 암호화 할 데이터
	[in] length : 원문의 길이
	[in] key : 키 구조체
	[in] ivec : 초기벡터
	[in] num : 의미없음
	Return Value : 
	Note : 
*/
void S_AES_CFB8_Decrypt(U8 *in, U8 *out, U32 length, AES_KEY_ST *key, U8 *ivec, unsigned int *num)
{
    unsigned int n;

    assert(in && out && key && ivec && num);
    assert(*num == 0);

    for(n=0 ; n < length ; ++n)
	S_AES_CFBR_Decrypt_Block(&in[n],&out[n],8,key,ivec);
}