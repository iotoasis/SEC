/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     rand_sha256.c

	 Creadted by DEV3

************************************************/ 

#ifndef NO_RANDOM

#include "../include/rand.h"
#include "../include/lsh256.h"
#include <time.h>
#include <memory.h>
#ifdef WIN32
#include <process.h>
#include <windows.h>
#else
#include <unistd.h>
#endif
#include <stdlib.h>

static U8 lsh256state[32];

/*	
	Name : S_GenerateSeed_LSH256
	Description: 랜덤값 생성을 위해 SEED값을 LSH256 해시알고리즘으로 생성한다.
	Parameters
	Return Value : 
	Note : 
*/
void S_GenerateSeed_LSH256()
{
	register U16 tmp16;
	register U8 *tmp8;
#ifdef _WINDOWS_
	register U32 count;
	register HDC hScrDC;
	U16 w, h;
#else
	U32 count;
#endif

	tmp8 = lsh256state;

#ifdef _WINDOWS_
	tmp16 = getpid();
	hScrDC = CreateDC("DISPLAY", NULL, NULL, NULL);
	w = GetDeviceCaps(hScrDC, HORZRES);
	h = GetDeviceCaps(hScrDC, VERTRES);
	count = GetTickCount();
	w = w ^ tmp16 ^ (U16)count;
	memcpy(tmp8, &w, 2);
	h = h ^ tmp16 ^ (U16)(count >> 16);
	memcpy(tmp8+2, &h, 2);
	S_LSH256(tmp8, tmp8, 4);
	DeleteDC(hScrDC);
#else
	tmp16 = getpid();
	count = tmp16 ^ time(NULL);
	S_LSH256(tmp8, (U8*)&count, 4);
#endif
}

/*	
	Name : tn_GenerateRandom_LSH256
	Description: LSH256 해시알고리즘을 사용하여 랜덤값을 생성한다.
	Parameters
	[out] out : 생성된 랜덤값
	[in] bytes : 생성할 랜덤값의 길이
	Return Value : 
	Note : 
*/
void tn_GenerateRandom_LSH256(U8 *out, U32 bytes)
{
	register U8 *tmp8;
	register U8 *o;

	tmp8 = lsh256state;
	o = out;
	
	while(bytes > 32)
	{		
		S_LSH256(tmp8, tmp8, 32);
		memcpy(o, tmp8, 32);
		bytes -= 32;
		o += 32;
	}
	if(bytes != 0)
	{
		S_LSH256(tmp8, tmp8, 32);
		memcpy(o, tmp8, bytes);
	}
}

/*	
	Name : S_GenerateRandom_LSH256
	Description: SEED값을 생성한 후 LSH256 해시알고리즘을 사용하여 랜덤값을 생성한다.
	Parameters
	[out] out : 생성된 랜덤값
	[in] bytes : 생성할 랜덤값의 길이
	Return Value : 
	Note : 
*/
void S_GenerateRandom_LSH256(U8 *out, U32 bytes)
{
	static int lsh256_init = 1;

	if(lsh256_init)
	{
		S_GenerateSeed_LSH256();
		lsh256_init = 0;
	}
	tn_GenerateRandom_LSH256(out, bytes);
}

#endif


