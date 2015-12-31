/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     lsh256.c

	 Creadted by DEV3

************************************************/

#ifndef NO_LSH256

#include <string.h>
#include "../include/typeconvert.h"
#include "../include/lsh256.h"

//step constants
static U32 SC256[NS256][8] = {
	{ 0x917caf90, 0x6c1b10a2, 0x6f352943, 0xcf778243, 0x2ceb7472, 0x29e96ff2, 0x8a9ba428, 0x2eeb2642 },
	{ 0x0e2c4021, 0x872bb30e, 0xa45e6cb2, 0x46f9c612, 0x185fe69e, 0x1359621b, 0x263fccb2, 0x1a116870 },
	{ 0x3a6c612f, 0xb2dec195, 0x02cb1f56, 0x40bfd858, 0x784684b6, 0x6cbb7d2e, 0x660c7ed8, 0x2b79d88a },
	{ 0xa6cd9069, 0x91a05747, 0xcdea7558, 0x00983098, 0xbecb3b2e, 0x2838ab9a, 0x728b573e, 0xa55262b5 },
	{ 0x745dfa0f, 0x31f79ed8, 0xb85fce25, 0x98c8c898, 0x8a0669ec, 0x60e445c2, 0xfde295b0, 0xf7b5185a },
	{ 0xd2580983, 0x29967709, 0x182df3dd, 0x61916130, 0x90705676, 0x452a0822, 0xe07846ad, 0xaccd7351 },
	{ 0x2a618d55, 0xc00d8032, 0x4621d0f5, 0xf2f29191, 0x00c6cd06, 0x6f322a67, 0x58bef48d, 0x7a40c4fd },
	{ 0x8beee27f, 0xcd8db2f2, 0x67f2c63b, 0xe5842383, 0xc793d306, 0xa15c91d6, 0x17b381e5, 0xbb05c277 },
	{ 0x7ad1620a, 0x5b40a5bf, 0x5ab901a2, 0x69a7a768, 0x5b66d9cd, 0xfdee6877, 0xcb3566fc, 0xc0c83a32 },
	{ 0x4c336c84, 0x9be6651a, 0x13baa3fc, 0x114f0fd1, 0xc240a728, 0xec56e074, 0x009c63c7, 0x89026cf2 },
	{ 0x7f9ff0d0, 0x824b7fb5, 0xce5ea00f, 0x605ee0e2, 0x02e7cfea, 0x43375560, 0x9d002ac7, 0x8b6f5f7b },
	{ 0x1f90c14f, 0xcdcb3537, 0x2cfeafdd, 0xbf3fc342, 0xeab7b9ec, 0x7a8cb5a3, 0x9d2af264, 0xfacedb06 },
	{ 0xb052106e, 0x99006d04, 0x2bae8d09, 0xff030601, 0xa271a6d6, 0x0742591d, 0xc81d5701, 0xc9a9e200 },
	{ 0x02627f1e, 0x996d719d, 0xda3b9634, 0x02090800, 0x14187d78, 0x499b7624, 0xe57458c9, 0x738be2c9 },
	{ 0x64e19d20, 0x06df0f36, 0x15d1cb0e, 0x0b110802, 0x2c95f58c, 0xe5119a6d, 0x59cd22ae, 0xff6eac3c },
	{ 0x467ebd84, 0xe5ee453c, 0xe79cd923, 0x1c190a0d, 0xc28b81b8, 0xf6ac0852, 0x26efd107, 0x6e1ae93b },
	{ 0xc53c41ca, 0xd4338221, 0x8475fd0a, 0x35231729, 0x4e0d3a7a, 0xa2b45b48, 0x16c0d82d, 0x890424a9 },
	{ 0x017e0c8f, 0x07b5a3f5, 0xfa73078e, 0x583a405e, 0x5b47b4c8, 0x570fa3ea, 0xd7990543, 0x8d28ce32 },
	{ 0x7f8a9b90, 0xbd5998fc, 0x6d7a9688, 0x927a9eb6, 0xa2fc7d23, 0x66b38e41, 0x709e491a, 0xb5f700bf },
	{ 0x0a262c0f, 0x16f295b9, 0xe8111ef5, 0x0d195548, 0x9f79a0c5, 0x1a41cfa7, 0x0ee7638a, 0xacf7c074 },
	{ 0x30523b19, 0x09884ecf, 0xf93014dd, 0x266e9d55, 0x191a6664, 0x5c1176c1, 0xf64aed98, 0xa4b83520 },
	{ 0x828d5449, 0x91d71dd8, 0x2944f2d6, 0x950bf27b, 0x3380ca7d, 0x6d88381d, 0x4138868e, 0x5ced55c4 },
	{ 0x0fe19dcb, 0x68f4f669, 0x6e37c8ff, 0xa0fe6e10, 0xb44b47b0, 0xf5c0558a, 0x79bf14cf, 0x4a431a20 },
	{ 0xf17f68da, 0x5deb5fd1, 0xa600c86d, 0x9f6c7eb0, 0xff92f864, 0xb615e07f, 0x38d3e448, 0x8d5d3a6a },
	{ 0x70e843cb, 0x494b312e, 0xa6c93613, 0x0beb2f4f, 0x928b5d63, 0xcbf66035, 0x0cb82c80, 0xea97a4f7 },
	{ 0x592c0f3b, 0x947c5f77, 0x6fff49b9, 0xf71a7e5a, 0x1de8c0f5, 0xc2569600, 0xc4e4ac8c, 0x823c9ce1 }
};

//IV for LSH-256-256
static U32 IV256[16] = {
	0x46a10f1f, 0xfddce486, 0xb41443a8, 0x198e6b9d, 0x3304388d, 0xb0f5a3c7, 0xb36061c4, 0x7adbd553,
	0x105d5378, 0x2f74de54, 0x5c2f2d95, 0xf2553fbe, 0x8051357a, 0x138668c8, 0x47aa4484, 0xe01afb41
};

//rotation amounts
static const int gamma256[8] = { 0, 8, 16, 24, 24, 16, 8, 0 };


static U32 m[3][16];
static U32 T[16];
static U32 S[16];
static U32 vl, vr;

INLINE void me(int l, int idx1, int idx2, int idx3, int tau1, int tau2)
{
	m[idx1][l] = m[idx2][l] + m[idx3][tau1];
	m[idx1][l + 8] = m[idx2][l + 8] + m[idx3][tau2];
}

INLINE void step0(int j, int l, int idx, int gamma, int rsigma1, int rsigma2, LSH256_CTX* state)
{
	// MsgAdd
	state->cv256[l] ^= m[idx][l];
	state->cv256[l + 8] ^= m[idx][l + 8];

	// Mix
	vl = state->cv256[l];
	vr = state->cv256[l + 8];
	vl += vr;
	vl = ROL32(vl, 29);
	vl ^= SC256[j][l];
	vr += vl;
	vr = ROL32(vr, 1);
	vl += vr;
	vr = ROL32(vr, gamma);

	// WordPerm
	T[rsigma1] = vl;
	T[rsigma2] = vr;
}

INLINE void step1(int j, int l, int idx, int gamma, int rsigma1, int rsigma2, U32 con)
{
	// MsgAdd
	S[l] ^= m[idx][l];
	S[l + 8] ^= m[idx][l + 8];

	// Mix & WordPerm

	S[l] += S[l + 8];
	S[l] = ROL32(S[l], 29);
	S[l] ^= con;
	S[l + 8] += S[l];
	S[l + 8] = ROL32(S[l + 8], 1);
	T[rsigma1] = S[l]+S[l + 8];
	T[rsigma2] = ROL32(S[l + 8], gamma);

}

INLINE void step2(int j, int l, int idx, int gamma, int rsigma1, int rsigma2, U32 con)
{
	// MsgAdd
	T[l] ^= m[idx][l];
	T[l + 8] ^= m[idx][l + 8];

	// Mix & WordPerm

	T[l] += T[l + 8];
	T[l] = ROL32(T[l], 5);
	T[l] ^= con;
	T[l + 8] += T[l];
	T[l + 8] = ROL32(T[l + 8], 17);
	S[rsigma1] = T[l]+T[l + 8];
	S[rsigma2] = ROL32(T[l + 8], gamma);
}

INLINE void step1_iv(int j, int l, int gamma, int rsigma1, int rsigma2)
{
	// Mix
	vl = IV256[l];
	vr = IV256[l + 8];
	vl += vr;
	vl = ROL32(vl, 29);
	vl ^= SC256[j][l];
	vr += vl;
	vr = ROL32(vr, 1);
	vl += vr;
	vr = ROL32(vr, gamma);

	// WordPerm
	T[rsigma1] = vl;
	T[rsigma2] = vr;
}

INLINE void step2_iv(int j, int l, int gamma, int rsigma1, int rsigma2)
{
	// Mix
	vl = T[l];
	vr = T[l + 8];
	vl += vr;
	vl = ROL32(vl, 5);
	vl ^= SC256[j][l];
	vr += vl;
	vr = ROL32(vr, 17);
	vl += vr;
	vr = ROL32(vr, gamma);

	// WordPerm
	IV256[rsigma1] = vl;
	IV256[rsigma2] = vr;
}

void compress256(LSH256_CTX * state, const U8 * datablock) 
{
	int l;

	//message expansion to m[0], m[1]
	for(l = 0; l < 32; l++)
	{
		m[0][l] = U8TO32_LE(datablock + 4 * l);
	}

	step0(0, 0, 0, 0, 9, 12, state);	step0(0, 1, 0, 8, 10, 15, state);
	step0(0, 2, 0, 16, 8, 14, state);	step0(0, 3, 0, 24, 11, 13, state);
	step0(0, 4, 0, 24, 1, 4, state);	step0(0, 5, 0, 16, 2, 7, state);
	step0(0, 6, 0, 8, 0, 6, state);		step0(0, 7, 0, 0, 3, 5, state);

	step2(1, 0, 1, 0, 9,  12, 0x0e2c4021);	step2(1, 1, 1, 8, 10,  15, 0x872bb30e);
	step2(1, 2, 1, 16, 8, 14, 0xa45e6cb2);	step2(1, 3, 1, 24, 11, 13, 0x46f9c612);
	step2(1, 4, 1, 24, 1, 4 , 0x185fe69e);	step2(1, 5, 1, 16, 2,   7, 0x1359621b);
	step2(1, 6, 1, 8, 0,   6, 0x263fccb2);	step2(1, 7, 1, 0, 3,   5 , 0x1a116870);

	me(0, 2, 1, 0, 3, 11); step1(2, 0, 2,  0,  9,12, 0x3a6c612f);	me(1, 2, 1, 0, 2, 10); step1(2, 1, 2,  8, 10,15, 0xb2dec195);
	me(2, 2, 1, 0, 0,  8); step1(2, 2, 2, 16,  8,14, 0x02cb1f56);	me(3, 2, 1, 0, 1,  9); step1(2, 3, 2, 24, 11,13, 0x40bfd858);
	me(4, 2, 1, 0, 7, 15); step1(2, 4, 2, 24,  1, 4, 0x784684b6);	me(5, 2, 1, 0, 4, 12); step1(2, 5, 2, 16,  2, 7, 0x6cbb7d2e);
	me(6, 2, 1, 0, 5, 13); step1(2, 6, 2,  8,  0, 6, 0x660c7ed8);	me(7, 2, 1, 0, 6, 14); step1(2, 7, 2,  0,  3, 5, 0x2b79d88a);
	me(0, 0, 2, 1, 3, 11); step2(3, 0, 0, 0, 9,  12, 0xa6cd9069);	me(1, 0, 2, 1, 2, 10); step2(3, 1, 0, 8, 10, 15, 0x91a05747);
	me(2, 0, 2, 1, 0,  8); step2(3, 2, 0, 16, 8, 14, 0xcdea7558);	me(3, 0, 2, 1, 1,  9); step2(3, 3, 0, 24, 11,13, 0x00983098);
	me(4, 0, 2, 1, 7, 15); step2(3, 4, 0, 24, 1,  4, 0xbecb3b2e);	me(5, 0, 2, 1, 4, 12); step2(3, 5, 0, 16, 2,  7, 0x2838ab9a);
	me(6, 0, 2, 1, 5, 13); step2(3, 6, 0, 8, 0,   6, 0x728b573e);	me(7, 0, 2, 1, 6, 14); step2(3, 7, 0, 0, 3,   5, 0xa55262b5);
	me(0, 1, 0, 2, 3, 11); step1(4, 0, 1, 0, 9,  12, 0x745dfa0f);	me(1, 1, 0, 2, 2, 10); step1(4, 1, 1, 8, 10, 15, 0x31f79ed8);
	me(2, 1, 0, 2, 0,  8); step1(4, 2, 1, 16, 8, 14, 0xb85fce25);	me(3, 1, 0, 2, 1,  9); step1(4, 3, 1, 24, 11,13, 0x98c8c898);
	me(4, 1, 0, 2, 7, 15); step1(4, 4, 1, 24, 1,  4, 0x8a0669ec);	me(5, 1, 0, 2, 4, 12); step1(4, 5, 1, 16, 2,  7, 0x60e445c2);
	me(6, 1, 0, 2, 5, 13); step1(4, 6, 1, 8, 0,   6, 0xfde295b0);	me(7, 1, 0, 2, 6, 14); step1(4, 7, 1, 0, 3,   5, 0xf7b5185a);
	me(0, 2, 1, 0, 3, 11); step2(5, 0, 2, 0, 9,  12, 0xd2580983);	me(1, 2, 1, 0, 2, 10); step2(5, 1, 2, 8, 10, 15, 0x29967709);
	me(2, 2, 1, 0, 0,  8); step2(5, 2, 2, 16, 8, 14, 0x182df3dd);	me(3, 2, 1, 0, 1,  9); step2(5, 3, 2, 24, 11,13, 0x61916130);
	me(4, 2, 1, 0, 7, 15); step2(5, 4, 2, 24, 1,  4, 0x90705676);	me(5, 2, 1, 0, 4, 12); step2(5, 5, 2, 16, 2,  7, 0x452a0822);
	me(6, 2, 1, 0, 5, 13); step2(5, 6, 2, 8, 0,   6, 0xe07846ad);	me(7, 2, 1, 0, 6, 14); step2(5, 7, 2, 0, 3,   5, 0xaccd7351);
	me(0, 0, 2, 1, 3, 11); step1(6, 0, 0, 0, 9,  12, 0x2a618d55);	me(1, 0, 2, 1, 2, 10); step1(6, 1, 0, 8, 10, 15, 0xc00d8032);
	me(2, 0, 2, 1, 0,  8); step1(6, 2, 0, 16, 8, 14, 0x4621d0f5);	me(3, 0, 2, 1, 1,  9); step1(6, 3, 0, 24, 11,13, 0xf2f29191);
	me(4, 0, 2, 1, 7, 15); step1(6, 4, 0, 24, 1,  4, 0x00c6cd06);	me(5, 0, 2, 1, 4, 12); step1(6, 5, 0, 16, 2,  7, 0x6f322a67);
	me(6, 0, 2, 1, 5, 13); step1(6, 6, 0, 8, 0,   6, 0x58bef48d);	me(7, 0, 2, 1, 6, 14); step1(6, 7, 0, 0, 3,   5, 0x7a40c4fd);
	me(0, 1, 0, 2, 3, 11); step2(7, 0, 1, 0, 9,  12, 0x8beee27f);	me(1, 1, 0, 2, 2, 10); step2(7, 1, 1, 8, 10, 15, 0xcd8db2f2);
	me(2, 1, 0, 2, 0,  8); step2(7, 2, 1, 16, 8, 14, 0x67f2c63b);	me(3, 1, 0, 2, 1,  9); step2(7, 3, 1, 24, 11,13, 0xe5842383);
	me(4, 1, 0, 2, 7, 15); step2(7, 4, 1, 24, 1,  4, 0xc793d306);	me(5, 1, 0, 2, 4, 12); step2(7, 5, 1, 16, 2,  7, 0xa15c91d6);
	me(6, 1, 0, 2, 5, 13); step2(7, 6, 1, 8, 0,   6, 0x17b381e5);	me(7, 1, 0, 2, 6, 14); step2(7, 7, 1, 0, 3,   5, 0xbb05c277);

	me(0, 2, 1, 0, 3, 11); step1( 8, 0, 2,  0,  9,12, 0x7ad1620a);	me(1, 2, 1, 0, 2, 10); step1( 8, 1, 2,  8, 10,15, 0x5b40a5bf);
	me(2, 2, 1, 0, 0,  8); step1( 8, 2, 2, 16,  8,14, 0x5ab901a2);	me(3, 2, 1, 0, 1,  9); step1( 8, 3, 2, 24, 11,13, 0x69a7a768);
	me(4, 2, 1, 0, 7, 15); step1( 8, 4, 2, 24,  1, 4, 0x5b66d9cd);	me(5, 2, 1, 0, 4, 12); step1( 8, 5, 2, 16,  2, 7, 0xfdee6877);
	me(6, 2, 1, 0, 5, 13); step1( 8, 6, 2,  8,  0, 6, 0xcb3566fc);	me(7, 2, 1, 0, 6, 14); step1( 8, 7, 2,  0,  3, 5, 0xc0c83a32);
	me(0, 0, 2, 1, 3, 11); step2( 9, 0, 0, 0, 9,  12, 0x4c336c84);	me(1, 0, 2, 1, 2, 10); step2( 9, 1, 0, 8, 10, 15, 0x9be6651a);
	me(2, 0, 2, 1, 0,  8); step2( 9, 2, 0, 16, 8, 14, 0x13baa3fc);	me(3, 0, 2, 1, 1,  9); step2( 9, 3, 0, 24, 11,13, 0x114f0fd1);
	me(4, 0, 2, 1, 7, 15); step2( 9, 4, 0, 24, 1,  4, 0xc240a728);	me(5, 0, 2, 1, 4, 12); step2( 9, 5, 0, 16, 2,  7, 0xec56e074);
	me(6, 0, 2, 1, 5, 13); step2( 9, 6, 0, 8, 0,   6, 0x009c63c7);	me(7, 0, 2, 1, 6, 14); step2( 9, 7, 0, 0, 3,   5, 0x89026cf2);
	me(0, 1, 0, 2, 3, 11); step1(10, 0, 1, 0, 9,  12, 0x7f9ff0d0);	me(1, 1, 0, 2, 2, 10); step1(10, 1, 1, 8, 10, 15, 0x824b7fb5);
	me(2, 1, 0, 2, 0,  8); step1(10, 2, 1, 16, 8, 14, 0xce5ea00f);	me(3, 1, 0, 2, 1,  9); step1(10, 3, 1, 24, 11,13, 0x605ee0e2);
	me(4, 1, 0, 2, 7, 15); step1(10, 4, 1, 24, 1,  4, 0x02e7cfea);	me(5, 1, 0, 2, 4, 12); step1(10, 5, 1, 16, 2,  7, 0x43375560);
	me(6, 1, 0, 2, 5, 13); step1(10, 6, 1, 8, 0,   6, 0x9d002ac7);	me(7, 1, 0, 2, 6, 14); step1(10, 7, 1, 0, 3,   5, 0x8b6f5f7b);
	me(0, 2, 1, 0, 3, 11); step2(11, 0, 2, 0, 9,  12, 0x1f90c14f);	me(1, 2, 1, 0, 2, 10); step2(11, 1, 2, 8, 10, 15, 0xcdcb3537);
	me(2, 2, 1, 0, 0,  8); step2(11, 2, 2, 16, 8, 14, 0x2cfeafdd);	me(3, 2, 1, 0, 1,  9); step2(11, 3, 2, 24, 11,13, 0xbf3fc342);
	me(4, 2, 1, 0, 7, 15); step2(11, 4, 2, 24, 1,  4, 0xeab7b9ec);	me(5, 2, 1, 0, 4, 12); step2(11, 5, 2, 16, 2,  7, 0x7a8cb5a3);
	me(6, 2, 1, 0, 5, 13); step2(11, 6, 2, 8, 0,   6, 0x9d2af264);	me(7, 2, 1, 0, 6, 14); step2(11, 7, 2, 0, 3,   5, 0xfacedb06);
	me(0, 0, 2, 1, 3, 11); step1(12, 0, 0, 0, 9,  12, 0xb052106e);	me(1, 0, 2, 1, 2, 10); step1(12, 1, 0, 8, 10, 15, 0x99006d04);
	me(2, 0, 2, 1, 0,  8); step1(12, 2, 0, 16, 8, 14, 0x2bae8d09);	me(3, 0, 2, 1, 1,  9); step1(12, 3, 0, 24, 11,13, 0xff030601);
	me(4, 0, 2, 1, 7, 15); step1(12, 4, 0, 24, 1,  4, 0xa271a6d6);	me(5, 0, 2, 1, 4, 12); step1(12, 5, 0, 16, 2,  7, 0x0742591d);
	me(6, 0, 2, 1, 5, 13); step1(12, 6, 0, 8, 0,   6, 0xc81d5701);	me(7, 0, 2, 1, 6, 14); step1(12, 7, 0, 0, 3,   5, 0xc9a9e200);
	me(0, 1, 0, 2, 3, 11); step2(13, 0, 1, 0, 9,  12, 0x02627f1e);	me(1, 1, 0, 2, 2, 10); step2(13, 1, 1, 8, 10, 15, 0x996d719d);
	me(2, 1, 0, 2, 0,  8); step2(13, 2, 1, 16, 8, 14, 0xda3b9634);	me(3, 1, 0, 2, 1,  9); step2(13, 3, 1, 24, 11,13, 0x02090800);
	me(4, 1, 0, 2, 7, 15); step2(13, 4, 1, 24, 1,  4, 0x14187d78);	me(5, 1, 0, 2, 4, 12); step2(13, 5, 1, 16, 2,  7, 0x499b7624);
	me(6, 1, 0, 2, 5, 13); step2(13, 6, 1, 8, 0,   6, 0xe57458c9);	me(7, 1, 0, 2, 6, 14); step2(13, 7, 1, 0, 3,   5, 0x738be2c9);

	me(0, 2, 1, 0, 3, 11); step1(14, 0, 2,  0,  9,12, 0x64e19d20);	me(1, 2, 1, 0, 2, 10); step1(14, 1, 2,  8, 10,15, 0x06df0f36);
	me(2, 2, 1, 0, 0,  8); step1(14, 2, 2, 16,  8,14, 0x15d1cb0e);	me(3, 2, 1, 0, 1,  9); step1(14, 3, 2, 24, 11,13, 0x0b110802);
	me(4, 2, 1, 0, 7, 15); step1(14, 4, 2, 24,  1, 4, 0x2c95f58c);	me(5, 2, 1, 0, 4, 12); step1(14, 5, 2, 16,  2, 7, 0xe5119a6d);
	me(6, 2, 1, 0, 5, 13); step1(14, 6, 2,  8,  0, 6, 0x59cd22ae);	me(7, 2, 1, 0, 6, 14); step1(14, 7, 2,  0,  3, 5, 0xff6eac3c);
	me(0, 0, 2, 1, 3, 11); step2(15, 0, 0, 0, 9,  12, 0x467ebd84);	me(1, 0, 2, 1, 2, 10); step2(15, 1, 0, 8, 10, 15, 0xe5ee453c);
	me(2, 0, 2, 1, 0,  8); step2(15, 2, 0, 16, 8, 14, 0xe79cd923);	me(3, 0, 2, 1, 1,  9); step2(15, 3, 0, 24, 11,13, 0x1c190a0d);
	me(4, 0, 2, 1, 7, 15); step2(15, 4, 0, 24, 1,  4, 0xc28b81b8);	me(5, 0, 2, 1, 4, 12); step2(15, 5, 0, 16, 2,  7, 0xf6ac0852);
	me(6, 0, 2, 1, 5, 13); step2(15, 6, 0, 8, 0,   6, 0x26efd107);	me(7, 0, 2, 1, 6, 14); step2(15, 7, 0, 0, 3,   5, 0x6e1ae93b);
	me(0, 1, 0, 2, 3, 11); step1(16, 0, 1, 0, 9,  12, 0xc53c41ca);	me(1, 1, 0, 2, 2, 10); step1(16, 1, 1, 8, 10, 15, 0xd4338221);
	me(2, 1, 0, 2, 0,  8); step1(16, 2, 1, 16, 8, 14, 0x8475fd0a);	me(3, 1, 0, 2, 1,  9); step1(16, 3, 1, 24, 11,13, 0x35231729);
	me(4, 1, 0, 2, 7, 15); step1(16, 4, 1, 24, 1,  4, 0x4e0d3a7a);	me(5, 1, 0, 2, 4, 12); step1(16, 5, 1, 16, 2,  7, 0xa2b45b48);
	me(6, 1, 0, 2, 5, 13); step1(16, 6, 1, 8, 0,   6, 0x16c0d82d);	me(7, 1, 0, 2, 6, 14); step1(16, 7, 1, 0, 3,   5, 0x890424a9);
	me(0, 2, 1, 0, 3, 11); step2(17, 0, 2, 0, 9,  12, 0x017e0c8f);	me(1, 2, 1, 0, 2, 10); step2(17, 1, 2, 8, 10, 15, 0x07b5a3f5);
	me(2, 2, 1, 0, 0,  8); step2(17, 2, 2, 16, 8, 14, 0xfa73078e);	me(3, 2, 1, 0, 1,  9); step2(17, 3, 2, 24, 11,13, 0x583a405e);
	me(4, 2, 1, 0, 7, 15); step2(17, 4, 2, 24, 1,  4, 0x5b47b4c8);	me(5, 2, 1, 0, 4, 12); step2(17, 5, 2, 16, 2,  7, 0x570fa3ea);
	me(6, 2, 1, 0, 5, 13); step2(17, 6, 2, 8, 0,   6, 0xd7990543);	me(7, 2, 1, 0, 6, 14); step2(17, 7, 2, 0, 3,   5, 0x8d28ce32);
	me(0, 0, 2, 1, 3, 11); step1(18, 0, 0, 0, 9,  12, 0x7f8a9b90);	me(1, 0, 2, 1, 2, 10); step1(18, 1, 0, 8, 10, 15, 0xbd5998fc);
	me(2, 0, 2, 1, 0,  8); step1(18, 2, 0, 16, 8, 14, 0x6d7a9688);	me(3, 0, 2, 1, 1,  9); step1(18, 3, 0, 24, 11,13, 0x927a9eb6);
	me(4, 0, 2, 1, 7, 15); step1(18, 4, 0, 24, 1,  4, 0xa2fc7d23);	me(5, 0, 2, 1, 4, 12); step1(18, 5, 0, 16, 2,  7, 0x66b38e41);
	me(6, 0, 2, 1, 5, 13); step1(18, 6, 0, 8, 0,   6, 0x709e491a);	me(7, 0, 2, 1, 6, 14); step1(18, 7, 0, 0, 3,   5, 0xb5f700bf);
	me(0, 1, 0, 2, 3, 11); step2(19, 0, 1, 0, 9,  12, 0x0a262c0f);	me(1, 1, 0, 2, 2, 10); step2(19, 1, 1, 8, 10, 15, 0x16f295b9);
	me(2, 1, 0, 2, 0,  8); step2(19, 2, 1, 16, 8, 14, 0xe8111ef5);	me(3, 1, 0, 2, 1,  9); step2(19, 3, 1, 24, 11,13, 0x0d195548);
	me(4, 1, 0, 2, 7, 15); step2(19, 4, 1, 24, 1,  4, 0x9f79a0c5);	me(5, 1, 0, 2, 4, 12); step2(19, 5, 1, 16, 2,  7, 0x1a41cfa7);
	me(6, 1, 0, 2, 5, 13); step2(19, 6, 1, 8, 0,   6, 0x0ee7638a);	me(7, 1, 0, 2, 6, 14); step2(19, 7, 1, 0, 3,   5, 0xacf7c074);

	me(0, 2, 1, 0, 3, 11); step1(20, 0, 2,  0,  9,12, 0x30523b19);	me(1, 2, 1, 0, 2, 10); step1(20, 1, 2,  8, 10,15, 0x09884ecf);
	me(2, 2, 1, 0, 0,  8); step1(20, 2, 2, 16,  8,14, 0xf93014dd);	me(3, 2, 1, 0, 1,  9); step1(20, 3, 2, 24, 11,13, 0x266e9d55);
	me(4, 2, 1, 0, 7, 15); step1(20, 4, 2, 24,  1,4, 0x191a6664);	me(5, 2, 1, 0, 4, 12); step1(20, 5, 2, 16,  2, 7, 0x5c1176c1);
	me(6, 2, 1, 0, 5, 13); step1(20, 6, 2,  8,  0,6, 0xf64aed98);	me(7, 2, 1, 0, 6, 14); step1(20, 7, 2,  0,  3, 5, 0xa4b83520);
	me(0, 0, 2, 1, 3, 11); step2(21, 0, 0, 0, 9,  12, 0x828d5449);	me(1, 0, 2, 1, 2, 10); step2(21, 1, 0, 8, 10, 15, 0x91d71dd8);
	me(2, 0, 2, 1, 0,  8); step2(21, 2, 0, 16, 8, 14, 0x2944f2d6);	me(3, 0, 2, 1, 1,  9); step2(21, 3, 0, 24, 11,13, 0x950bf27b);
	me(4, 0, 2, 1, 7, 15); step2(21, 4, 0, 24, 1,  4, 0x3380ca7d);	me(5, 0, 2, 1, 4, 12); step2(21, 5, 0, 16, 2,  7, 0x6d88381d);
	me(6, 0, 2, 1, 5, 13); step2(21, 6, 0, 8, 0,   6, 0x4138868e);	me(7, 0, 2, 1, 6, 14); step2(21, 7, 0, 0, 3,   5, 0x5ced55c4);
	me(0, 1, 0, 2, 3, 11); step1(22, 0, 1, 0, 9,  12, 0x0fe19dcb);	me(1, 1, 0, 2, 2, 10); step1(22, 1, 1, 8, 10, 15, 0x68f4f669);
	me(2, 1, 0, 2, 0,  8); step1(22, 2, 1, 16, 8, 14, 0x6e37c8ff);	me(3, 1, 0, 2, 1,  9); step1(22, 3, 1, 24, 11,13, 0xa0fe6e10);
	me(4, 1, 0, 2, 7, 15); step1(22, 4, 1, 24, 1,  4, 0xb44b47b0);	me(5, 1, 0, 2, 4, 12); step1(22, 5, 1, 16, 2,  7, 0xf5c0558a);
	me(6, 1, 0, 2, 5, 13); step1(22, 6, 1, 8, 0,   6, 0x79bf14cf);	me(7, 1, 0, 2, 6, 14); step1(22, 7, 1, 0, 3,   5, 0x4a431a20);
	me(0, 2, 1, 0, 3, 11); step2(23, 0, 2, 0, 9,  12, 0xf17f68da);	me(1, 2, 1, 0, 2, 10); step2(23, 1, 2, 8, 10, 15, 0x5deb5fd1);
	me(2, 2, 1, 0, 0,  8); step2(23, 2, 2, 16, 8, 14, 0xa600c86d);	me(3, 2, 1, 0, 1,  9); step2(23, 3, 2, 24, 11,13, 0x9f6c7eb0);
	me(4, 2, 1, 0, 7, 15); step2(23, 4, 2, 24, 1,  4, 0xff92f864);	me(5, 2, 1, 0, 4, 12); step2(23, 5, 2, 16, 2,  7, 0xb615e07f);
	me(6, 2, 1, 0, 5, 13); step2(23, 6, 2, 8, 0,   6, 0x38d3e448);	me(7, 2, 1, 0, 6, 14); step2(23, 7, 2, 0, 3,   5, 0x8d5d3a6a);
	me(0, 0, 2, 1, 3, 11); step1(24, 0, 0, 0, 9,  12, 0x70e843cb);	me(1, 0, 2, 1, 2, 10); step1(24, 1, 0, 8, 10, 15, 0x494b312e);
	me(2, 0, 2, 1, 0,  8); step1(24, 2, 0, 16, 8, 14, 0xa6c93613);	me(3, 0, 2, 1, 1,  9); step1(24, 3, 0, 24, 11,13, 0x0beb2f4f);
	me(4, 0, 2, 1, 7, 15); step1(24, 4, 0, 24, 1,  4, 0x928b5d63);	me(5, 0, 2, 1, 4, 12); step1(24, 5, 0, 16, 2,  7, 0xcbf66035);
	me(6, 0, 2, 1, 5, 13); step1(24, 6, 0, 8, 0,   6, 0x0cb82c80);	me(7, 0, 2, 1, 6, 14); step1(24, 7, 0, 0, 3,   5, 0xea97a4f7);
	me(0, 1, 0, 2, 3, 11); step2(25, 0, 1, 0, 9,  12, 0x592c0f3b);	me(1, 1, 0, 2, 2, 10); step2(25, 1, 1, 8, 10, 15, 0x947c5f77);
	me(2, 1, 0, 2, 0,  8); step2(25, 2, 1, 16, 8, 14, 0x6fff49b9);	me(3, 1, 0, 2, 1,  9); step2(25, 3, 1, 24, 11,13, 0xf71a7e5a);
	me(4, 1, 0, 2, 7, 15); step2(25, 4, 1, 24, 1,  4, 0x1de8c0f5);	me(5, 1, 0, 2, 4, 12); step2(25, 5, 1, 16, 2,  7, 0xc2569600);
	me(6, 1, 0, 2, 5, 13); step2(25, 6, 1, 8, 0,   6, 0xc4e4ac8c);	me(7, 1, 0, 2, 6, 14); step2(25, 7, 1, 0, 3,   5, 0x823c9ce1);

	state->cv256[ 0]=S[ 0]^(m[1][ 0] + m[0][ 3]);
	state->cv256[ 8]=S[ 8]^(m[1][ 8] + m[0][11]);
	state->cv256[ 1]=S[ 1]^(m[1][ 1] + m[0][ 2]);
	state->cv256[ 9]=S[ 9]^(m[1][ 9] + m[0][10]);
	state->cv256[ 2]=S[ 2]^(m[1][ 2] + m[0][ 0]);
	state->cv256[10]=S[10]^(m[1][10] + m[0][ 8]);
	state->cv256[ 3]=S[ 3]^(m[1][ 3] + m[0][ 1]);
	state->cv256[11]=S[11]^(m[1][11] + m[0][ 9]);
	state->cv256[ 4]=S[ 4]^(m[1][ 4] + m[0][ 7]);
	state->cv256[12]=S[12]^(m[1][12] + m[0][15]);
	state->cv256[ 5]=S[ 5]^(m[1][ 5] + m[0][ 4]);
	state->cv256[13]=S[13]^(m[1][13] + m[0][12]);
	state->cv256[ 6]=S[ 6]^(m[1][ 6] + m[0][ 5]);
	state->cv256[14]=S[14]^(m[1][14] + m[0][13]);
	state->cv256[ 7]=S[ 7]^(m[1] [7] + m[0][ 6]);
	state->cv256[15]=S[15]^(m[1][15] + m[0][14]);

	return;
}

void GetIV256(int hashbitlen)
{
	int j;

	memset(IV256, 0, 16 * sizeof(U32));
	IV256[0] = 32;
	IV256[1] = (U32)hashbitlen;

	for (j = 0; j < NS256; j += 2)
	{
		step1_iv(j, 0, 0, 9, 12);
		step1_iv(j, 1, 8, 10, 15);
		step1_iv(j, 2, 16, 8, 14);
		step1_iv(j, 3, 24, 11, 13);
		step1_iv(j, 4, 24, 1, 4);
		step1_iv(j, 5, 16, 2, 7);
		step1_iv(j, 6, 8, 0, 6);
		step1_iv(j, 7, 0, 3, 5);

		step2_iv(j + 1, 0, 0, 9, 12);
		step2_iv(j + 1, 1, 8, 10, 15);
		step2_iv(j + 1, 2, 16, 8, 14);
		step2_iv(j + 1, 3, 24, 11, 13);
		step2_iv(j + 1, 4, 24, 1, 4);
		step2_iv(j + 1, 5, 16, 2, 7);
		step2_iv(j + 1, 6, 8, 0, 6);
		step2_iv(j + 1, 7, 0, 3, 5);
	}

	return;
}

/*	
	Name : sha256_init
	Description: SHA256 해쉬를 위해 컨텍스트를 초기화한다.
	Parameters
	[out] ctx : 초기화할 컨텍스트 구조체
	Return Value : 
	Note : 
*/
void lsh256_init( LSH256_CTX *ctx )
{

	memcpy(ctx->cv256, IV256, sizeof(IV256));

	ctx->hashbitlen = 256;
	return ;
	/*
	if ((hashbitlen <0) || (hashbitlen>256))
		return BAD_HASHBITLEN;
	else 
	{
		if (hashbitlen < 256) GetIV256(hashbitlen);
		memcpy(state->cv256, IV256, sizeof(IV256));
	}
	state->hashbitlen = hashbitlen;
	return SUCCESS;
	*/
}

/*	
	Name : lsh256_update
	Description: 전체 데이터에 대한 중간단계 해시계산을 수행한다.
	Parameters
	[in/out] ctx : 해시계산값이 저장되는 컨텍스트 구조체
	[in] input : 해시를 수행할 전체 데이터
	[in] length : 해시를 수행할 전체 데이터 길이값
	Return Value : 
	Note : 
*/
void lsh256_update( LSH256_CTX *ctx, U8 *input, U32 length )
{
	U64 numBlocks, temp, databitlen = length*8;
	U32 pos1, pos2;
	int i;
	numBlocks = ((U64)databitlen >> 10) + 1;

	for (i = 0; i < numBlocks - 1; i++){
		compress256(ctx, input);
		input += 128;
	}

	//computation of the state->Last256 block (padded)
	//if databitlen not multiple of 1024
	/*
	databitlen = 1024*(numBlocks-1) + 8*pos1 + pos2,
	0<=pos1<128, 0<=pos2<7
	*/
	if((U32)(databitlen & 0x3ff))
	{
		temp = (numBlocks - 1) << 7; //temp = 128*(numBlocks-1)
		pos1 = (U32)((databitlen >> 3) - temp);
		pos2 = (U32)(databitlen & 0x7);

		//if databitlen not multiple of 8
		if (pos2)
		{
			memcpy(ctx->Last256, input, pos1*sizeof(char));
			ctx->Last256[pos1] = (input[pos1] & (0xff << (8 - pos2))) ^ (1 << (7 - pos2));
			if (pos1 != 127) memset(ctx->Last256 + pos1 + 1, 0, (127 - pos1)*sizeof(char));
		}
		//if databitlen multiple of 8
		else
		{
			memcpy(ctx->Last256, input, pos1*sizeof(char));
			ctx->Last256[pos1] = 0x80;
			if (pos1 != 127) memset(ctx->Last256 + pos1 + 1, 0, (127 - pos1)*sizeof(char));
		}
	}
	//if databitlen multiple of 1024
	else
	{
		ctx->Last256[0] = 0x80;
		memset(ctx->Last256 + 1, 0, 127 * sizeof(U8));
	}
	// end of computation of the state->Last256 block

	return;
}

/*	
	Name : lsh256_final
	Description: 패딩작업을 거쳐 최종단계 해시값을 생성한다.
	Parameters
	[in] ctx : 해시계산값이 저장되는 컨텍스트 구조체
	[out] digest : 256비트 해시결과값
	Return Value : 
	Note : 
*/
void lsh256_final( LSH256_CTX *ctx, U8 *digest)
{
	int l;
	U32 H[8];

	compress256(ctx, ctx->Last256);

	for (l = 0; l < 8; l++) H[l] = (ctx->cv256[l]) ^ (ctx->cv256[l + 8]);

	for (l = 0; l < (ctx->hashbitlen) >> 3; l++){
		//		hashval[l] = (U8)(ROR32(H[l >> 2], (l << 3) & 0x1f) ); 
		digest[l] = (U8)(H[l >> 2] >> ((l << 3) & 0x1f)); //0,8,16,24,0,,.. = 8*l (mod 32) = (l<<3)&0x1f
	}

	return;
}

/*	
	Name : S_LSH256
	Description: 데이터에 대한 SHA256 해시값을 계산한다.
	Parameters
	[out] out : 해시 결과값
	[in] in : 해시 대상 원문
	[in] bytes : 해시 대상 원문 길이값
	Return Value : 
	Note : 
*/
void S_LSH256(U8 *out, U8 *in, U32 bytes)
{
	LSH256_CTX ctx;
	lsh256_init(&ctx);
	lsh256_update(&ctx, in, bytes);
	lsh256_final(&ctx,out);
}

#endif