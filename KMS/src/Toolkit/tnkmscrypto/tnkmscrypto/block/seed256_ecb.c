/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     seed256_ecb.c, SEED256 알고리즘, ECB mode

	 Creadted by DEV3

************************************************/

#include "../include/seed256.h"
#include "../include/typeconvert.h"

/*	
	Name : S_SEED256_ECB_Encrypt
	Description: 암호키를 이용하여 SEED ECB 모드 암호알고리즘으로 입력 데이터를 암호화 한다
	Parameters
	[in] in : 암호화 할 데이터
	[out] out : 암호화 된 데이터
	[in] key : SEED 키 구조체
	[in] bytes : 암호화 할 데이터 길이
	Return Value : 
	Note : 
*/
void S_SEED256_ECB_Encrypt(U8 *in, U8 *out, SEED256_KEY *key, long bytes)
{
	register U32 tin0, tin1, tin2, tin3;
	register U32 tout0, tout1, tout2, tout3;
	register long l = bytes;
	U32 tmp[4];

	for(l -= 16; l >= 0; l -= 16)
	{
		U8ToU32(in, tin0); tmp[0] = tin0;
		U8ToU32(in, tin1); tmp[1] = tin1;
		U8ToU32(in, tin2); tmp[2] = tin2;
		U8ToU32(in, tin3); tmp[3] = tin3;
		S_SEED256_Encrypt(tmp, key);
		tout0 = tmp[0]; U32ToU8(tout0, out);
		tout1 = tmp[1]; U32ToU8(tout1, out);
		tout2 = tmp[2]; U32ToU8(tout2, out);
		tout3 = tmp[3]; U32ToU8(tout3, out);
	}
	if(l != -16)
	{
		U8ToU32n2(in, tin0, tin1, tin2, tin3, l + 16);
		tmp[0] = tin0;
		tmp[1] = tin1;
		tmp[2] = tin2;
		tmp[3] = tin3;
		S_SEED256_Encrypt(tmp, key);
		tout0 = tmp[0]; U32ToU8(tout0, out);
		tout1 = tmp[1]; U32ToU8(tout1, out);
		tout2 = tmp[2]; U32ToU8(tout2, out);
		tout3 = tmp[3]; U32ToU8(tout3, out);
	}	
}

/*	
	Name : S_SEED256_ECB_Decrypt
	Description: 암호키를 이용하여 SEED ECB 모드 암호알고리즘으로 암호화된 데이터를 복호화 한다
	Parameters
	[in] in : 복호화 할 데이터
	[out] out : 복호화 된 데이터
	[in] key : SEED 키 구조체
	[in] bytes : 복호화 할 데이터 길이
	Return Value : 
	Note : 
*/
void S_SEED256_ECB_Decrypt(U8 *in, U8 *out, SEED256_KEY *key, long bytes)
{
	register U32 tin0, tin1, tin2, tin3;
	register U32 tout0, tout1, tout2, tout3;
	register long l = bytes;
	U32 tmp[4];

	for(l -= 16; l >= 0; l -= 16)
	{
		U8ToU32(in, tin0); tmp[0] = tin0;
		U8ToU32(in, tin1); tmp[1] = tin1;
		U8ToU32(in, tin2); tmp[2] = tin2;
		U8ToU32(in, tin3); tmp[3] = tin3;
		S_SEED256_Decrypt(tmp, key);
		tout0 = tmp[0]; U32ToU8(tout0, out);
		tout1 = tmp[1]; U32ToU8(tout1, out);
		tout2 = tmp[2]; U32ToU8(tout2, out);
		tout3 = tmp[3]; U32ToU8(tout3, out);
	}
	if(l != -16)
	{
		U8ToU32(in, tin0); tmp[0] = tin0;
		U8ToU32(in, tin1); tmp[1] = tin1;
		U8ToU32(in, tin2); tmp[2] = tin2;
		U8ToU32(in, tin3); tmp[3] = tin3;
		S_SEED256_Decrypt(tmp, key);
		tout0 = tmp[0];
		tout1 = tmp[1];
		tout2 = tmp[2];
		tout3 = tmp[3];
		U32ToU8n2(tout0, tout1, tout2, tout3, out, l + 16);
	}
}
