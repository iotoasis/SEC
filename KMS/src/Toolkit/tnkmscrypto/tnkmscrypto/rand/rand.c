/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     rand.c

	 Creadted by DEV3

************************************************/ 

#ifndef NO_RANDOM

#include "../include/rand.h"
#include "../include/sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
	Name : S_GenerateRandom
 	Description : 선택 모드에 따라서 SHA256 해시 알고리즘을 사용하여 랜덤 값을 생성 한다.
 	Parameters
 	[out] out : 생성된 랜덤 데이터
	[in] bytes : 생성할 랜덤 데이터의 길이
	[in] mode : 선택 모드(SAH256 : 0)
 	Return Value :
 	Note :
 */
void S_GenerateRandom(U8 *out, U32 bytes, int mode)
{
	if(mode)
	{

	}
	else
	{
		S_GenerateRandom_SHA256(out, bytes); 
	}
}

#define STATE_SIZE			1023
#define MD_DIGEST_LENGTH	16

static int state_num = 0, state_index = 0;
static U8 state[STATE_SIZE + MD_DIGEST_LENGTH];
static U8 md[MD_DIGEST_LENGTH];
static long md_count[1] = {0};

/*
	Name : S_RAND_Seed
 	Description : SEED 데이터를 SHA256 해시 알고리즘으로 처리한다.
 	Parameters 	
	[out] buf : 생성된 SHA256 해시 데이터
	[in] num : 생성될 SHA256 해시 데이터 크기
 	Return Value :
 	Note :
 */
void S_RAND_Seed(U8 *buf, int num)
{
	int i, j, k, st_idx, st_num;
	SHA256_CTX m;

	st_idx = state_index;
	st_num = state_num;

	state_index = state_index + num;
	if (state_index > STATE_SIZE)
	{
		state_index %= STATE_SIZE;
		state_num = STATE_SIZE;
	}
	else if (state_num < STATE_SIZE)	
	{
		if (state_index > state_num)
			state_num = state_index;
	}
	
	for (i = 0; i < num; i += MD_DIGEST_LENGTH)     
	{
		j = num - i;
		j = (j > MD_DIGEST_LENGTH) ? MD_DIGEST_LENGTH : j;

		sha256_init(&m);
		sha256_update(&m, md, MD_DIGEST_LENGTH);
		k = st_idx + j - STATE_SIZE;
		if (k > 0)
		{
			sha256_update(&m, &(state[st_idx]), j - k);
			sha256_update(&m, &(state[0]), k);
		}
		else
			sha256_update(&m, &(state[st_idx]), j);
			
		sha256_update(&m, buf, j);
		sha256_final(&m, md);

		buf += j;

		for (k = 0; k < j; k ++)
		{
			state[st_idx++] ^= md[k];
			if(st_idx >= STATE_SIZE)
			{
				st_idx = 0;
				st_num = STATE_SIZE;
			}
		}
	}

	memset((char *)&m, 0, sizeof(m));
}

/*
	Name : S_RAND_Bytes
 	Description :  랜덤값 생성을 위해 SEED값을 SHA256 해시 알고리즘으로 생성한다.
 	Parameters
 	[out] buf : 생성된 랜덤 데이터 
	[in] num : 	생성할 랜덤 데이터 크기 
 	Return Value :
 	Note :
 */
void S_RAND_Bytes(U8 *buf, int num)
{
	int i, j, k, st_num, st_idx;
	SHA256_CTX m;
	static int init = 1;
	U32 l;
	long md_c[2];
	U8 local_md[MD_DIGEST_LENGTH];
	int num_ceil;

	if (init)
	{
		init = 0;
		S_RAND_Seed((U8*)&m, sizeof(m));
		l = time(NULL);
		S_RAND_Seed((U8*)&l, sizeof(l));
	}

	num_ceil = (1 + (num - 1) / (MD_DIGEST_LENGTH / 2)) * (MD_DIGEST_LENGTH / 2);

	st_idx = state_index;
	st_num = state_num;
	md_c[0] = md_count[0];
	memcpy(local_md, md, sizeof md);

	state_index += num_ceil;
	if (state_index > state_num)
		state_index = state_index % state_num;

	md_count[0] += 1;

	while (num > 0)
	{
		j = (num >= MD_DIGEST_LENGTH / 2) ? MD_DIGEST_LENGTH / 2 : num;
		num -= j;
		sha256_init(&m);
		sha256_update(&m, local_md, MD_DIGEST_LENGTH);
		sha256_update(&m, (unsigned char *)&(md_c[0]), sizeof(md_c));

		k = (st_idx + MD_DIGEST_LENGTH / 2) - st_num;
		if (k > 0)
		{
			sha256_update(&m, &(state[st_idx]), MD_DIGEST_LENGTH / 2 - k);
			sha256_update(&m, &(state[0]), k);
		}
		else
			sha256_update(&m, &(state[st_idx]), MD_DIGEST_LENGTH / 2);
		sha256_final(&m, local_md);

		for (i = 0; i < MD_DIGEST_LENGTH / 2; i++)
		{
			state[st_idx++] ^= local_md[i];
			if (st_idx >= st_num)
					st_idx = 0;
			if (i < j)
				*(buf++) = local_md[i + MD_DIGEST_LENGTH / 2];
		}
	}

	sha256_init(&m);
	sha256_update(&m, (unsigned char *)&(md_c[0]), sizeof(md_c));
	sha256_update(&m, local_md, MD_DIGEST_LENGTH);
	sha256_update(&m, md, MD_DIGEST_LENGTH);
	sha256_final(&m, md);

	memset(&m, 0, sizeof(m));
}

#endif