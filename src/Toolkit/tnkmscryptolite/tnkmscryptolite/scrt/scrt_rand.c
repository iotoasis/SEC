/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     scrt_rand.c

	 Creadted by DEV3

************************************************/ 

#include "../include/scrt.h"
#include "../include/rand.h"
#include <stdio.h>
#include <string.h>

/***************************************************************************
----scrt_GenerateRandom

	parameter : <in>	bytes 		: 생성될 random string의 byte 수 
						mode		: NID_sha256
				<out>	out			: random string
***************************************************************************/
/*	
	Name : SCRT_GenerateRandom
	Description : 랜덤값 생성함수 
	Parameters
	[in] bytes : 생성할 랜덤데이터 길이
	[in] mode : NID_lsh256
	[in/out] out : 생성된 랜덤데이터
	Note : 성공 0, 실패 0xF0000036
*/
SRESULT SCRT_GenerateRandom( U32 bytes, int mode, U8 *out) 
{
	SRESULT E_SR;
	E_SR = S_FAILED | SL_RANDOM | SF_SCRT_GEN_RANDOM ;
	
	switch(mode)
	{
	case NID_lsh256	: S_GenerateRandom_LSH256(out, bytes); break;
	default : return E_SR | SR_RANDOM_ALGO_NOT_SUPPORTED	;
	}

	return S_SUCCESS;
}


