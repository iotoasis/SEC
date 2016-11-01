/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     lea_ctr.c, LEA 알고리즘, CTR 운영모드

	 Creadted by DEV3

************************************************/

#ifndef NO_LEA

#include <stdio.h>
#include "../include/typeconvert.h"
#include "../include/lea.h"

/* increment counter (128-bit int) by 1 */
static void ctr128_inc(unsigned char *counter) {
	unsigned int n=16;
	unsigned char c;

	do {
		--n;
		c = counter[n];
		++c;
		counter[n] = c;
		if (c) return;
	} while (n);
}

static void ctr128_inc_aligned(unsigned char *counter) {
	unsigned int *data,c,n;
	const union { long one; char little; } is_endian = {1};

	if (is_endian.little) {
		ctr128_inc(counter);
		return;
	}

	data = (unsigned int *)counter;
	n = 16/sizeof(unsigned int);
	do {
		--n;
		c = data[n];
		++c;
		data[n] = c;
		if (c) return;
	} while (n);
}

int S_LEA_CTR128_Encrypt(LEA_KEY *key, U8 *ctr, const U8 *in, unsigned int in_len, U8 *out)
{
	unsigned char block[128];
	unsigned int remainBlock = in_len >> 4, i=0;


	if (!key){
		return -1;
	}

	if (!ctr){
		return -3;
	}

	if (in_len > 0 && (!out || !in)){
		return -4;
	}

	for (; remainBlock >= 1; remainBlock -= 1, in += 0x10, out += 0x10)
	{
		S_LEA_Encrypt(key, ctr, block);
		
		XOR8x16(out, block, in);

		ctr128_inc_aligned(ctr);
	}

	if(in_len & 0xf)
	{
		S_LEA_Encrypt(key, ctr, block);

		for(i = 0; i < (in_len & 0xf); i++)
			out[i] = block[i] ^ in[i];
	}

	return 0;
}

int S_LEA_CTR128_Decrypt(LEA_KEY *key, U8 *ctr, const U8 *in, unsigned int in_len, U8 *out)
{
	int ret;

	ret = S_LEA_CTR128_Encrypt(key, ctr, in, in_len, out);

	return ret;
}

#endif