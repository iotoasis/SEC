/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     seed256_cbc.c, SEED256 알고리즘, CBC mode

	 Creadted by DEV3

************************************************/

#include "../include/seed256.h"
#include "../include/typeconvert.h"
/*	
	Name : S_SEED256_CBC_Encrypt
	Description: 암호키 와 초기벡터를 이용하여 SEED CBC 모드 암호알고리즘으로 입력 데이터를 암호화 한다
	Parameters
	[in] in : 암호화할 데이터
	[out] out : 암호화된 데이터	
	[in] key : 키 구조체	
	[in] bytes : 암호화 대상 평문 데이터 길이값
	[in] iv : 초기 벡터값
	Return Value : 
	Note : 
*/	
void S_SEED256_CBC_Encrypt(U8 *in, U8 *out, SEED256_KEY *key, long bytes, U8 *iv)
{
	register U32 tin0, tin1, tin2, tin3;
	register U32 tout0, tout1, tout2, tout3;
	register long l = bytes;
	U8 *ivtemp = iv;
	U32 tin[4];

	U8ToU32(iv, tout0);
	U8ToU32(iv, tout1);
	U8ToU32(iv, tout2);
	U8ToU32(iv, tout3);
	for(l -= 16; l >= 0; l -= 16)
	{
		U8ToU32(in, tin0);
		U8ToU32(in, tin1);
		U8ToU32(in, tin2);
		U8ToU32(in, tin3);
		tin0 ^= tout0; tin[0] = tin0;
		tin1 ^= tout1; tin[1] = tin1;
		tin2 ^= tout2; tin[2] = tin2;
		tin3 ^= tout3; tin[3] = tin3;
		S_SEED256_Encrypt(tin, key);
		tout0 = tin[0]; U32ToU8(tout0, out);
		tout1 = tin[1]; U32ToU8(tout1, out);
		tout2 = tin[2]; U32ToU8(tout2, out);
		tout3 = tin[3]; U32ToU8(tout3, out);
	}
	if(l != -16)
	{
		U8ToU32n2(in, tin0, tin1, tin2, tin3, l + 16);
		tin0 ^= tout0; tin[0] = tin0;
		tin1 ^= tout1; tin[1] = tin1;
		tin2 ^= tout2; tin[2] = tin2;
		tin3 ^= tout3; tin[3] = tin3;
		S_SEED256_Encrypt(tin, key);
		tout0 = tin[0]; U32ToU8(tout0, out);
		tout1 = tin[1]; U32ToU8(tout1, out);
		tout2 = tin[2]; U32ToU8(tout2, out);
		tout3 = tin[3]; U32ToU8(tout3, out);
	}	
	iv = ivtemp;
	U32ToU8(tout0,iv);
	U32ToU8(tout1,iv);
	U32ToU8(tout2,iv);
	U32ToU8(tout3,iv);
}
/*	
	Name : S_SEED256_CBC_Decrypt
	Description: 암호키 와 초기벡터를 이용하여 SEED CBC 모드 암호알고리즘으로 입력 데이터를 복호화 한다
	Parameters
	[in] in : 복호화할 데이터	
	[out] out : 복호화된 데이터
	[in] key : 키 구조체	
	[in] bytes : 복호화 대상 평문 데이터 길이값
	[in] iv : 초기 벡터값
	Return Value : 
	Note : 
*/	
void S_SEED256_CBC_Decrypt(U8 *in, U8 *out, SEED256_KEY *key, long bytes, U8 *iv)
{
	register U32 tin0, tin1, tin2, tin3;
	register U32 tout0, tout1, tout2, tout3, xor0, xor1, xor2, xor3;
	register long l = bytes;
	U8 *ivtemp = iv;
	U32 tin[4];
	
	U8ToU32(iv, xor0);
	U8ToU32(iv, xor1);
	U8ToU32(iv, xor2);
	U8ToU32(iv, xor3);
	for(l -= 16; l >= 0; l -= 16)
	{
		U8ToU32(in, tin0); tin[0] = tin0;
		U8ToU32(in, tin1); tin[1] = tin1;
		U8ToU32(in, tin2); tin[2] = tin2;
		U8ToU32(in, tin3); tin[3] = tin3;
		S_SEED256_Decrypt(tin, key);
		tout0 = tin[0] ^ xor0;
		tout1 = tin[1] ^ xor1;
		tout2 = tin[2] ^ xor2;
		tout3 = tin[3] ^ xor3;
		U32ToU8(tout0, out);
		U32ToU8(tout1, out);
		U32ToU8(tout2, out);
		U32ToU8(tout3, out);
		xor0 = tin0;
		xor1 = tin1;
		xor2 = tin2;
		xor3 = tin3;
	}
	if(l != -16)
	{
		U8ToU32(in, tin0); tin[0] = tin0;
		U8ToU32(in, tin1); tin[1] = tin1;
		U8ToU32(in, tin2); tin[2] = tin2;
		U8ToU32(in, tin3); tin[3] = tin3;
		S_SEED256_Decrypt(tin, key);
		tout0 = tin[0] ^ xor0;
		tout1 = tin[1] ^ xor1;
		tout2 = tin[2] ^ xor2;
		tout3 = tin[3] ^ xor3;
		U32ToU8n2(tout0, tout1, tout2, tout3, out, l + 16);
	}
	iv = ivtemp;
	U32ToU8(xor0,iv);
	U32ToU8(xor1,iv);
	U32ToU8(xor2,iv);
	U32ToU8(xor3,iv);
	tin0=tin1=tin2=tin3=0;
	tout0=tout1=tout2=tout3=0;
	xor0=xor1=xor2=xor3=0;
	tin[0]=tin[1]=tin[2]=tin[3]=0;
}

