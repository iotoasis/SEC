/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     lea.c, LEA 알고리즘

	 Creadted by DEV3

************************************************/

#ifndef NO_LEA

#include <stdio.h>
#include "../include/typeconvert.h"
#include "../include/lea.h"

#if (USE_BUILT_IN)
#if defined(_MSC_VER)
#include <stdlib.h>
#define ROR(W,i) _lrotr(W, i)
#define ROL(W,i) _lrotl(W, i)
#else	/*	#if defined(_MSC_VER)	*/
#define ROR(W,i) (((W) >> (i)) | ((W) << (32 - (i))))
#define ROL(W,i) (((W) << (i)) | ((W) >> (32 - (i))))
#endif	/*	#if defined(_MSC_VER)	*/
#include <string.h>
#define lea_memcpy		memcpy
#define lea_memset		memset
#define lea_memcmp		memcmp
#else	/*	#if (USE_BUILT_IN)	*/
#define ROR(W,i) (((W) >> (i)) | ((W) << (32 - (i))))
#define ROL(W,i) (((W) << (i)) | ((W) >> (32 - (i))))
void lea_memcpy(void *dst, void *src, int count);
void lea_memset(void *dst, int val, int count);
void lea_memcmp(void *src1, void *src2, int count);
#endif

#define U32_in(x)            (*(U32*)(x))
#define U32_out(x, v)        {*((U32*)(x)) = (v);}

//	endianess
#if (defined(sparc)) ||	(defined(__powerpc__) || defined(__ppc__) || defined(__PPC__)) || defined(__BIG_ENDIAN__)
//	Microblaze, SuperH, AVR32, System/360(370), ESA/390, z/Architecture, PDP-10
//	big endian
#define ctow(c, w)	(*(w) = (((c)[3] << 24) | ((c)[2] << 16) | ((c)[1] << 8) | ((c)[0])))
#define wtoc(w, c)	((c)[0] = *(w), (c)[1] = (*(w) >> 8), (c)[2] = (*(w) >> 16), (c)[3] = (*(w) >> 24))
#define __ENDIAN__ "big endian"
#else
//	little endian
#define ctow(c, w)	(*(w) = *((unsigned int *)(c)))
#define wtoc(w, c)	(*((unsigned int *)(c)) = *(w))
#define __ENDIAN__ "little endian"
#endif

static const unsigned int delta[8][36] = {
	{0xc3efe9db, 0x87dfd3b7, 0x0fbfa76f, 0x1f7f4ede, 0x3efe9dbc, 0x7dfd3b78, 0xfbfa76f0, 0xf7f4ede1,
	0xefe9dbc3, 0xdfd3b787, 0xbfa76f0f, 0x7f4ede1f, 0xfe9dbc3e, 0xfd3b787d, 0xfa76f0fb, 0xf4ede1f7,
	0xe9dbc3ef, 0xd3b787df, 0xa76f0fbf, 0x4ede1f7f, 0x9dbc3efe, 0x3b787dfd, 0x76f0fbfa, 0xede1f7f4,
	0xdbc3efe9, 0xb787dfd3, 0x6f0fbfa7, 0xde1f7f4e, 0xbc3efe9d, 0x787dfd3b, 0xf0fbfa76, 0xe1f7f4eD,
	0xc3efe9db,	0x87dfd3b7, 0x0fbfa76f, 0x1f7f4ede},
	{0x44626b02, 0x88c4d604, 0x1189ac09, 0x23135812, 0x4626b024, 0x8c4d6048, 0x189ac091, 0x31358122,
	0x626b0244, 0xc4d60488, 0x89ac0911, 0x13581223, 0x26b02446, 0x4d60488c, 0x9ac09118, 0x35812231,
	0x6b024462, 0xd60488c4, 0xac091189, 0x58122313, 0xb0244626, 0x60488c4d, 0xc091189a, 0x81223135,
	0x0244626b, 0x0488c4d6, 0x091189ac, 0x12231358, 0x244626b0, 0x488c4d60, 0x91189ac0, 0x22313581,
	0x44626b02, 0x88c4d604, 0x1189ac09, 0x23135812},
	{0x79e27c8a, 0xf3c4f914, 0xe789f229, 0xcf13e453, 0x9e27c8a7, 0x3c4f914f, 0x789f229e, 0xf13e453c,
	0xe27c8a79, 0xc4f914f3, 0x89f229e7, 0x13e453cf, 0x27c8a79e, 0x4f914f3c, 0x9f229e78, 0x3e453cf1,
	0x7c8a79e2, 0xf914f3c4, 0xf229e789, 0xe453cf13, 0xc8a79e27, 0x914f3c4f, 0x229e789f, 0x453cf13e,
	0x8a79e27c, 0x14f3c4f9, 0x29e789f2, 0x53cf13e4, 0xa79e27c8, 0x4f3c4f91, 0x9e789f22, 0x3cf13e45,
	0x79e27c8a, 0xf3c4f914, 0xe789f229, 0xcf13e453},
	{0x78df30ec, 0xf1be61d8, 0xe37cc3b1, 0xc6f98763, 0x8df30ec7, 0x1be61d8f, 0x37cc3b1e, 0x6f98763c,
	0xdf30ec78, 0xbe61d8f1, 0x7cc3b1e3, 0xf98763c6, 0xf30ec78d, 0xe61d8f1b, 0xcc3b1e37, 0x98763c6f,
	0x30ec78df, 0x61d8f1be, 0xc3b1e37c, 0x8763c6f9, 0x0ec78df3, 0x1d8f1be6, 0x3b1e37cc, 0x763c6f98,
	0xec78df30, 0xd8f1be61, 0xb1e37cc3, 0x63c6f987, 0xc78df30e, 0x8f1be61d, 0x1e37cc3b, 0x3c6f9876,
	0x78df30ec,	0xf1be61d8, 0xe37cc3b1, 0xc6f98763},
	{0x715ea49e, 0xe2bd493c, 0xc57a9279, 0x8af524f3, 0x15ea49e7, 0x2bd493ce, 0x57a9279c, 0xaf524f38,
	0x5ea49e71, 0xbd493ce2, 0x7a9279c5, 0xf524f38a, 0xea49e715, 0xd493ce2b, 0xa9279c57, 0x524f38af,
	0xa49e715e, 0x493ce2bd, 0x9279c57a, 0x24f38af5, 0x49e715ea, 0x93ce2bd4, 0x279c57a9, 0x4f38af52,
	0x9e715ea4, 0x3ce2bd49, 0x79c57a92, 0xf38af524, 0xe715ea49, 0xce2bd493, 0x9c57a927, 0x38af524f,
	0x715ea49e,	0xe2bd493c, 0xc57a9279, 0x8af524f3},
	{0xc785da0a, 0x8f0bb415, 0x1e17682b, 0x3c2ed056, 0x785da0ac, 0xf0bb4158, 0xe17682b1, 0xc2ed0563,
	0x85da0ac7, 0x0bb4158f, 0x17682b1e, 0x2ed0563c, 0x5da0ac78, 0xbb4158f0, 0x7682b1e1, 0xed0563c2,
	0xda0ac785, 0xb4158f0b, 0x682b1e17, 0xd0563c2e, 0xa0ac785d, 0x4158f0bb, 0x82b1e176, 0x0563c2ed,
	0x0ac785da, 0x158f0bb4, 0x2b1e1768, 0x563c2ed0, 0xac785da0, 0x58f0bb41, 0xb1e17682, 0x63c2ed05,
	0xc785da0a, 0x8f0bb415, 0x1e17682b, 0x3c2ed056},
	{0xe04ef22a, 0xc09de455, 0x813bc8ab, 0x02779157, 0x04ef22ae, 0x09de455c, 0x13bc8ab8, 0x27791570,
	0x4ef22ae0, 0x9de455c0, 0x3bc8ab81, 0x77915702, 0xef22ae04, 0xde455c09, 0xbc8ab813, 0x79157027,
	0xf22ae04e, 0xe455c09d, 0xc8ab813b, 0x91570277, 0x22ae04ef, 0x455c09de, 0x8ab813bc, 0x15702779,
	0x2ae04ef2, 0x55c09de4, 0xab813bc8, 0x57027791, 0xae04ef22, 0x5c09de45, 0xb813bc8a, 0x70277915,
	0xe04ef22a,	0xc09de455, 0x813bc8ab, 0x02779157},
	{0xe5c40957, 0xcb8812af, 0x9710255f, 0x2e204abf, 0x5c40957e, 0xb8812afc, 0x710255f9, 0xe204abf2,
	0xc40957e5, 0x8812afcb, 0x10255f97, 0x204abf2e, 0x40957e5c, 0x812afcb8, 0x0255f971, 0x04abf2e2,
	0x0957e5c4, 0x12afcb88, 0x255f9710, 0x4abf2e20, 0x957e5c40, 0x2afcb881, 0x55f97102, 0xabf2e204,
	0x57e5c409, 0xafcb8812, 0x5f971025, 0xbf2e204a, 0x7e5c4095, 0xfcb8812a, 0xf9710255, 0xf2e204ab,
	0xe5c40957,	0xcb8812af, 0x9710255f, 0x2e204abf}
};

U32 swap_u32( U32 val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}

#ifdef _LEA_DEBUG
void ShowWord(unsigned int *src, int word_len)
{
	int i=0;

	for (i=0; i<word_len; i++)
		printf("%08X ", src[i]);
	printf("\n");

}
#endif

/*	
	Name : S_LEA_Keyschedule
	Description: LEA 키 설정
	Parameters
	[out] key : 키 구조체	 
	[in] pbKey : 입력 키 값	( bytes )
	[in] keyBits : 입력 키 길이 ( bytes length )
	Return Value : 성공일 경우 0, 실패일 경우 -1, -2 값
	Note : 
*/
int S_LEA_Keyschedule(LEA_KEY *key, const U8 *pbKey, unsigned int nKeyLen)
{
#ifdef _LEA_DEBUG	
	int i;
#endif	
	if( (!key) || (!pbKey)) return -1;

	switch(nKeyLen)
	{
	case 16:
#ifdef _LEA_DEBUG
		printf("pbKey : ");
		for(i=0; i<nKeyLen;i++)
			printf("%02X ", pbKey[i]);
		printf("\n");
		printf("delta[0][ 0] : [%08X], *((unsigned int *)pbKey) : [%08X], *((unsigned int *)pbKey) + delta[0][ 0] : [%08X] , ROL(*((unsigned int *)pbKey) + delta[0][ 0], 1) :  [%08X]\n", delta[0][ 0], *((unsigned int *)pbKey), *((unsigned int *)pbKey) + delta[0][ 0], ROL(*((unsigned int *)pbKey) + delta[0][ 0], 1));
#endif
#ifndef LEA_BIG_ENDIAN
		key->rk[  0] = ROL(*((unsigned int *)pbKey) + delta[0][ 0], 1);
#else
		key->rk[  0] = ROL(bswap32(*((unsigned int *)pbKey)) + delta[0][ 0], 1);
#endif
#ifdef _LEA_DEBUG
		printf("key->rk[  0] : [%08X], delta[1][ 1] : [%08X], key->rk[  0] + delta[1][ 1] : [%08X] , ROL(key->rk[  0] + delta[1][ 1], 1) :  [%08X]\n", key->rk[  0], key->rk[  0] + delta[1][ 1], delta[0][ 0], ROL(key->rk[  0] + delta[1][ 1], 1));
#endif	
		key->rk[  6] = ROL(key->rk[  0] + delta[1][ 1], 1);
#ifdef _LEA_DEBUG
		printf("key->rk[  6] : [%08X], delta[2][ 2] : [%08X], key->rk[  6] + delta[2][ 2] : [%08X] , ROL(key->rk[  6] + delta[2][ 2], 1) :  [%08X]\n", key->rk[  6], delta[2][ 2], key->rk[  6] + delta[2][ 2] , ROL(key->rk[  6] + delta[2][ 2], 1));
#endif	
		key->rk[ 12] = ROL(key->rk[  6] + delta[2][ 2], 1);
		key->rk[ 18] = ROL(key->rk[ 12] + delta[3][ 3], 1);
		key->rk[ 24] = ROL(key->rk[ 18] + delta[0][ 4], 1);
		key->rk[ 30] = ROL(key->rk[ 24] + delta[1][ 5], 1);
		key->rk[ 36] = ROL(key->rk[ 30] + delta[2][ 6], 1);
		key->rk[ 42] = ROL(key->rk[ 36] + delta[3][ 7], 1);
		key->rk[ 48] = ROL(key->rk[ 42] + delta[0][ 8], 1);
		key->rk[ 54] = ROL(key->rk[ 48] + delta[1][ 9], 1);
		key->rk[ 60] = ROL(key->rk[ 54] + delta[2][10], 1);
		key->rk[ 66] = ROL(key->rk[ 60] + delta[3][11], 1);
		key->rk[ 72] = ROL(key->rk[ 66] + delta[0][12], 1);
		key->rk[ 78] = ROL(key->rk[ 72] + delta[1][13], 1);
		key->rk[ 84] = ROL(key->rk[ 78] + delta[2][14], 1);
		key->rk[ 90] = ROL(key->rk[ 84] + delta[3][15], 1);
		key->rk[ 96] = ROL(key->rk[ 90] + delta[0][16], 1);
		key->rk[102] = ROL(key->rk[ 96] + delta[1][17], 1);
		key->rk[108] = ROL(key->rk[102] + delta[2][18], 1);
		key->rk[114] = ROL(key->rk[108] + delta[3][19], 1);
		key->rk[120] = ROL(key->rk[114] + delta[0][20], 1);
		key->rk[126] = ROL(key->rk[120] + delta[1][21], 1);
		key->rk[132] = ROL(key->rk[126] + delta[2][22], 1);
		key->rk[138] = ROL(key->rk[132] + delta[3][23], 1);

#ifndef LEA_BIG_ENDIAN
		key->rk[  1] = key->rk[  3] = key->rk[  5] = ROL(*((unsigned int *)pbKey + 1) + delta[0][ 1], 3);
#else
		key->rk[  1] = key->rk[  3] = key->rk[  5] = ROL(bswap32(*((unsigned int *)pbKey + 1)) + delta[0][ 1], 3);
#endif		
		key->rk[  7] = key->rk[  9] = key->rk[ 11] = ROL(key->rk[  1] + delta[1][ 2], 3);
		key->rk[ 13] = key->rk[ 15] = key->rk[ 17] = ROL(key->rk[  7] + delta[2][ 3], 3);
		key->rk[ 19] = key->rk[ 21] = key->rk[ 23] = ROL(key->rk[ 13] + delta[3][ 4], 3);
		key->rk[ 25] = key->rk[ 27] = key->rk[ 29] = ROL(key->rk[ 19] + delta[0][ 5], 3);
		key->rk[ 31] = key->rk[ 33] = key->rk[ 35] = ROL(key->rk[ 25] + delta[1][ 6], 3);
		key->rk[ 37] = key->rk[ 39] = key->rk[ 41] = ROL(key->rk[ 31] + delta[2][ 7], 3);
		key->rk[ 43] = key->rk[ 45] = key->rk[ 47] = ROL(key->rk[ 37] + delta[3][ 8], 3);
		key->rk[ 49] = key->rk[ 51] = key->rk[ 53] = ROL(key->rk[ 43] + delta[0][ 9], 3);
		key->rk[ 55] = key->rk[ 57] = key->rk[ 59] = ROL(key->rk[ 49] + delta[1][10], 3);
		key->rk[ 61] = key->rk[ 63] = key->rk[ 65] = ROL(key->rk[ 55] + delta[2][11], 3);
		key->rk[ 67] = key->rk[ 69] = key->rk[ 71] = ROL(key->rk[ 61] + delta[3][12], 3);
		key->rk[ 73] = key->rk[ 75] = key->rk[ 77] = ROL(key->rk[ 67] + delta[0][13], 3);
		key->rk[ 79] = key->rk[ 81] = key->rk[ 83] = ROL(key->rk[ 73] + delta[1][14], 3);
		key->rk[ 85] = key->rk[ 87] = key->rk[ 89] = ROL(key->rk[ 79] + delta[2][15], 3);
		key->rk[ 91] = key->rk[ 93] = key->rk[ 95] = ROL(key->rk[ 85] + delta[3][16], 3);
		key->rk[ 97] = key->rk[ 99] = key->rk[101] = ROL(key->rk[ 91] + delta[0][17], 3);
		key->rk[103] = key->rk[105] = key->rk[107] = ROL(key->rk[ 97] + delta[1][18], 3);
		key->rk[109] = key->rk[111] = key->rk[113] = ROL(key->rk[103] + delta[2][19], 3);
		key->rk[115] = key->rk[117] = key->rk[119] = ROL(key->rk[109] + delta[3][20], 3);
		key->rk[121] = key->rk[123] = key->rk[125] = ROL(key->rk[115] + delta[0][21], 3);
		key->rk[127] = key->rk[129] = key->rk[131] = ROL(key->rk[121] + delta[1][22], 3);
		key->rk[133] = key->rk[135] = key->rk[137] = ROL(key->rk[127] + delta[2][23], 3);
		key->rk[139] = key->rk[141] = key->rk[143] = ROL(key->rk[133] + delta[3][24], 3);

#ifndef LEA_BIG_ENDIAN
		key->rk[  2] = ROL(*((unsigned int *)pbKey + 2) + delta[0][ 2], 6);
#else
		key->rk[  2] = ROL(bswap32(*((unsigned int *)pbKey + 2)) + delta[0][ 2], 6);
#endif		
		key->rk[  8] = ROL(key->rk[  2] + delta[1][ 3], 6);
		key->rk[ 14] = ROL(key->rk[  8] + delta[2][ 4], 6);
		key->rk[ 20] = ROL(key->rk[ 14] + delta[3][ 5], 6);
		key->rk[ 26] = ROL(key->rk[ 20] + delta[0][ 6], 6);
		key->rk[ 32] = ROL(key->rk[ 26] + delta[1][ 7], 6);
		key->rk[ 38] = ROL(key->rk[ 32] + delta[2][ 8], 6);
		key->rk[ 44] = ROL(key->rk[ 38] + delta[3][ 9], 6);
		key->rk[ 50] = ROL(key->rk[ 44] + delta[0][10], 6);
		key->rk[ 56] = ROL(key->rk[ 50] + delta[1][11], 6);
		key->rk[ 62] = ROL(key->rk[ 56] + delta[2][12], 6);
		key->rk[ 68] = ROL(key->rk[ 62] + delta[3][13], 6);
		key->rk[ 74] = ROL(key->rk[ 68] + delta[0][14], 6);
		key->rk[ 80] = ROL(key->rk[ 74] + delta[1][15], 6);
		key->rk[ 86] = ROL(key->rk[ 80] + delta[2][16], 6);
		key->rk[ 92] = ROL(key->rk[ 86] + delta[3][17], 6);
		key->rk[ 98] = ROL(key->rk[ 92] + delta[0][18], 6);
		key->rk[104] = ROL(key->rk[ 98] + delta[1][19], 6);
		key->rk[110] = ROL(key->rk[104] + delta[2][20], 6);
		key->rk[116] = ROL(key->rk[110] + delta[3][21], 6);
		key->rk[122] = ROL(key->rk[116] + delta[0][22], 6);
		key->rk[128] = ROL(key->rk[122] + delta[1][23], 6);
		key->rk[134] = ROL(key->rk[128] + delta[2][24], 6);
		key->rk[140] = ROL(key->rk[134] + delta[3][25], 6);
		
#ifndef LEA_BIG_ENDIAN
		key->rk[  4] = ROL(*((unsigned int *)pbKey + 3) + delta[0][ 3], 11);
#else
		key->rk[  4] = ROL(bswap32(*((unsigned int *)pbKey + 3)) + delta[0][ 3], 11);
#endif		
		key->rk[ 10] = ROL(key->rk[  4] + delta[1][ 4], 11);
		key->rk[ 16] = ROL(key->rk[ 10] + delta[2][ 5], 11);
		key->rk[ 22] = ROL(key->rk[ 16] + delta[3][ 6], 11);
		key->rk[ 28] = ROL(key->rk[ 22] + delta[0][ 7], 11);
		key->rk[ 34] = ROL(key->rk[ 28] + delta[1][ 8], 11);
		key->rk[ 40] = ROL(key->rk[ 34] + delta[2][ 9], 11);
		key->rk[ 46] = ROL(key->rk[ 40] + delta[3][10], 11);
		key->rk[ 52] = ROL(key->rk[ 46] + delta[0][11], 11);
		key->rk[ 58] = ROL(key->rk[ 52] + delta[1][12], 11);
		key->rk[ 64] = ROL(key->rk[ 58] + delta[2][13], 11);
		key->rk[ 70] = ROL(key->rk[ 64] + delta[3][14], 11);
		key->rk[ 76] = ROL(key->rk[ 70] + delta[0][15], 11);
		key->rk[ 82] = ROL(key->rk[ 76] + delta[1][16], 11);
		key->rk[ 88] = ROL(key->rk[ 82] + delta[2][17], 11);
		key->rk[ 94] = ROL(key->rk[ 88] + delta[3][18], 11);
		key->rk[100] = ROL(key->rk[ 94] + delta[0][19], 11);
		key->rk[106] = ROL(key->rk[100] + delta[1][20], 11);
		key->rk[112] = ROL(key->rk[106] + delta[2][21], 11);
		key->rk[118] = ROL(key->rk[112] + delta[3][22], 11);
		key->rk[124] = ROL(key->rk[118] + delta[0][23], 11);
		key->rk[130] = ROL(key->rk[124] + delta[1][24], 11);
		key->rk[136] = ROL(key->rk[130] + delta[2][25], 11);
		key->rk[142] = ROL(key->rk[136] + delta[3][26], 11);
		break;

	case 24:
#ifndef LEA_BIG_ENDIAN
		key->rk[  0] = ROL(*((unsigned int *)pbKey) + delta[0][ 0], 1);
#else
		key->rk[  0] = ROL(bswap32(*((unsigned int *)pbKey)) + delta[0][ 0], 1);
#endif		
		key->rk[  6] = ROL(key->rk[  0] + delta[1][ 1], 1);
		key->rk[ 12] = ROL(key->rk[  6] + delta[2][ 2], 1);
		key->rk[ 18] = ROL(key->rk[ 12] + delta[3][ 3], 1);
		key->rk[ 24] = ROL(key->rk[ 18] + delta[4][ 4], 1);
		key->rk[ 30] = ROL(key->rk[ 24] + delta[5][ 5], 1);
		key->rk[ 36] = ROL(key->rk[ 30] + delta[0][ 6], 1);
		key->rk[ 42] = ROL(key->rk[ 36] + delta[1][ 7], 1);
		key->rk[ 48] = ROL(key->rk[ 42] + delta[2][ 8], 1);
		key->rk[ 54] = ROL(key->rk[ 48] + delta[3][ 9], 1);
		key->rk[ 60] = ROL(key->rk[ 54] + delta[4][10], 1);
		key->rk[ 66] = ROL(key->rk[ 60] + delta[5][11], 1);
		key->rk[ 72] = ROL(key->rk[ 66] + delta[0][12], 1);
		key->rk[ 78] = ROL(key->rk[ 72] + delta[1][13], 1);
		key->rk[ 84] = ROL(key->rk[ 78] + delta[2][14], 1);
		key->rk[ 90] = ROL(key->rk[ 84] + delta[3][15], 1);
		key->rk[ 96] = ROL(key->rk[ 90] + delta[4][16], 1);
		key->rk[102] = ROL(key->rk[ 96] + delta[5][17], 1);
		key->rk[108] = ROL(key->rk[102] + delta[0][18], 1);
		key->rk[114] = ROL(key->rk[108] + delta[1][19], 1);
		key->rk[120] = ROL(key->rk[114] + delta[2][20], 1);
		key->rk[126] = ROL(key->rk[120] + delta[3][21], 1);
		key->rk[132] = ROL(key->rk[126] + delta[4][22], 1);
		key->rk[138] = ROL(key->rk[132] + delta[5][23], 1);
		key->rk[144] = ROL(key->rk[138] + delta[0][24], 1);
		key->rk[150] = ROL(key->rk[144] + delta[1][25], 1);
		key->rk[156] = ROL(key->rk[150] + delta[2][26], 1);
		key->rk[162] = ROL(key->rk[156] + delta[3][27], 1);
		
#ifndef LEA_BIG_ENDIAN
		key->rk[  1] = ROL(*((unsigned int *)pbKey + 1) + delta[0][ 1], 3);
#else
		key->rk[  1] = ROL(bswap32(*((unsigned int *)pbKey + 1)) + delta[0][ 1], 3);
#endif		
		key->rk[  7] = ROL(key->rk[  1] + delta[1][ 2], 3);
		key->rk[ 13] = ROL(key->rk[  7] + delta[2][ 3], 3);
		key->rk[ 19] = ROL(key->rk[ 13] + delta[3][ 4], 3);
		key->rk[ 25] = ROL(key->rk[ 19] + delta[4][ 5], 3);
		key->rk[ 31] = ROL(key->rk[ 25] + delta[5][ 6], 3);
		key->rk[ 37] = ROL(key->rk[ 31] + delta[0][ 7], 3);
		key->rk[ 43] = ROL(key->rk[ 37] + delta[1][ 8], 3);
		key->rk[ 49] = ROL(key->rk[ 43] + delta[2][ 9], 3);
		key->rk[ 55] = ROL(key->rk[ 49] + delta[3][10], 3);
		key->rk[ 61] = ROL(key->rk[ 55] + delta[4][11], 3);
		key->rk[ 67] = ROL(key->rk[ 61] + delta[5][12], 3);
		key->rk[ 73] = ROL(key->rk[ 67] + delta[0][13], 3);
		key->rk[ 79] = ROL(key->rk[ 73] + delta[1][14], 3);
		key->rk[ 85] = ROL(key->rk[ 79] + delta[2][15], 3);
		key->rk[ 91] = ROL(key->rk[ 85] + delta[3][16], 3);
		key->rk[ 97] = ROL(key->rk[ 91] + delta[4][17], 3);
		key->rk[103] = ROL(key->rk[ 97] + delta[5][18], 3);
		key->rk[109] = ROL(key->rk[103] + delta[0][19], 3);
		key->rk[115] = ROL(key->rk[109] + delta[1][20], 3);
		key->rk[121] = ROL(key->rk[115] + delta[2][21], 3);
		key->rk[127] = ROL(key->rk[121] + delta[3][22], 3);
		key->rk[133] = ROL(key->rk[127] + delta[4][23], 3);
		key->rk[139] = ROL(key->rk[133] + delta[5][24], 3);
		key->rk[145] = ROL(key->rk[139] + delta[0][25], 3);
		key->rk[151] = ROL(key->rk[145] + delta[1][26], 3);
		key->rk[157] = ROL(key->rk[151] + delta[2][27], 3);
		key->rk[163] = ROL(key->rk[157] + delta[3][28], 3);

#ifndef LEA_BIG_ENDIAN
		key->rk[  2] = ROL(*((unsigned int *)pbKey + 2) + delta[0][ 2], 6);
#else
		key->rk[  2] = ROL(bswap32(*((unsigned int *)pbKey + 2)) + delta[0][ 2], 6);
#endif		
		key->rk[  8] = ROL(key->rk[  2] + delta[1][ 3], 6);
		key->rk[ 14] = ROL(key->rk[  8] + delta[2][ 4], 6);
		key->rk[ 20] = ROL(key->rk[ 14] + delta[3][ 5], 6);
		key->rk[ 26] = ROL(key->rk[ 20] + delta[4][ 6], 6);
		key->rk[ 32] = ROL(key->rk[ 26] + delta[5][ 7], 6);
		key->rk[ 38] = ROL(key->rk[ 32] + delta[0][ 8], 6);
		key->rk[ 44] = ROL(key->rk[ 38] + delta[1][ 9], 6);
		key->rk[ 50] = ROL(key->rk[ 44] + delta[2][10], 6);
		key->rk[ 56] = ROL(key->rk[ 50] + delta[3][11], 6);
		key->rk[ 62] = ROL(key->rk[ 56] + delta[4][12], 6);
		key->rk[ 68] = ROL(key->rk[ 62] + delta[5][13], 6);
		key->rk[ 74] = ROL(key->rk[ 68] + delta[0][14], 6);
		key->rk[ 80] = ROL(key->rk[ 74] + delta[1][15], 6);
		key->rk[ 86] = ROL(key->rk[ 80] + delta[2][16], 6);
		key->rk[ 92] = ROL(key->rk[ 86] + delta[3][17], 6);
		key->rk[ 98] = ROL(key->rk[ 92] + delta[4][18], 6);
		key->rk[104] = ROL(key->rk[ 98] + delta[5][19], 6);
		key->rk[110] = ROL(key->rk[104] + delta[0][20], 6);
		key->rk[116] = ROL(key->rk[110] + delta[1][21], 6);
		key->rk[122] = ROL(key->rk[116] + delta[2][22], 6);
		key->rk[128] = ROL(key->rk[122] + delta[3][23], 6);
		key->rk[134] = ROL(key->rk[128] + delta[4][24], 6);
		key->rk[140] = ROL(key->rk[134] + delta[5][25], 6);
		key->rk[146] = ROL(key->rk[140] + delta[0][26], 6);
		key->rk[152] = ROL(key->rk[146] + delta[1][27], 6);
		key->rk[158] = ROL(key->rk[152] + delta[2][28], 6);
		key->rk[164] = ROL(key->rk[158] + delta[3][29], 6);

#ifndef LEA_BIG_ENDIAN
		key->rk[  3] = ROL(*((unsigned int *)pbKey + 3) + delta[0][ 3], 11);
#else
		key->rk[  3] = ROL(bswap32(*((unsigned int *)pbKey + 3)) + delta[0][ 3], 11);	
#endif			
		key->rk[  9] = ROL(key->rk[  3] + delta[1][ 4], 11);
		key->rk[ 15] = ROL(key->rk[  9] + delta[2][ 5], 11);
		key->rk[ 21] = ROL(key->rk[ 15] + delta[3][ 6], 11);
		key->rk[ 27] = ROL(key->rk[ 21] + delta[4][ 7], 11);
		key->rk[ 33] = ROL(key->rk[ 27] + delta[5][ 8], 11);
		key->rk[ 39] = ROL(key->rk[ 33] + delta[0][ 9], 11);
		key->rk[ 45] = ROL(key->rk[ 39] + delta[1][10], 11);
		key->rk[ 51] = ROL(key->rk[ 45] + delta[2][11], 11);
		key->rk[ 57] = ROL(key->rk[ 51] + delta[3][12], 11);
		key->rk[ 63] = ROL(key->rk[ 57] + delta[4][13], 11);
		key->rk[ 69] = ROL(key->rk[ 63] + delta[5][14], 11);
		key->rk[ 75] = ROL(key->rk[ 69] + delta[0][15], 11);
		key->rk[ 81] = ROL(key->rk[ 75] + delta[1][16], 11);
		key->rk[ 87] = ROL(key->rk[ 81] + delta[2][17], 11);
		key->rk[ 93] = ROL(key->rk[ 87] + delta[3][18], 11);
		key->rk[ 99] = ROL(key->rk[ 93] + delta[4][19], 11);
		key->rk[105] = ROL(key->rk[ 99] + delta[5][20], 11);
		key->rk[111] = ROL(key->rk[105] + delta[0][21], 11);
		key->rk[117] = ROL(key->rk[111] + delta[1][22], 11);
		key->rk[123] = ROL(key->rk[117] + delta[2][23], 11);
		key->rk[129] = ROL(key->rk[123] + delta[3][24], 11);
		key->rk[135] = ROL(key->rk[129] + delta[4][25], 11);
		key->rk[141] = ROL(key->rk[135] + delta[5][26], 11);
		key->rk[147] = ROL(key->rk[141] + delta[0][27], 11);
		key->rk[153] = ROL(key->rk[147] + delta[1][28], 11);
		key->rk[159] = ROL(key->rk[153] + delta[2][29], 11);
		key->rk[165] = ROL(key->rk[159] + delta[3][30], 11);

#ifndef LEA_BIG_ENDIAN
		key->rk[  4] = ROL(*((unsigned int *)pbKey + 4) + delta[0][ 4], 13);
#else
		key->rk[  4] = ROL(bswap32(*((unsigned int *)pbKey + 4)) + delta[0][ 4], 13);	
#endif			
		key->rk[ 10] = ROL(key->rk[  4] + delta[1][ 5], 13);
		key->rk[ 16] = ROL(key->rk[ 10] + delta[2][ 6], 13);
		key->rk[ 22] = ROL(key->rk[ 16] + delta[3][ 7], 13);
		key->rk[ 28] = ROL(key->rk[ 22] + delta[4][ 8], 13);
		key->rk[ 34] = ROL(key->rk[ 28] + delta[5][ 9], 13);
		key->rk[ 40] = ROL(key->rk[ 34] + delta[0][10], 13);
		key->rk[ 46] = ROL(key->rk[ 40] + delta[1][11], 13);
		key->rk[ 52] = ROL(key->rk[ 46] + delta[2][12], 13);
		key->rk[ 58] = ROL(key->rk[ 52] + delta[3][13], 13);
		key->rk[ 64] = ROL(key->rk[ 58] + delta[4][14], 13);
		key->rk[ 70] = ROL(key->rk[ 64] + delta[5][15], 13);
		key->rk[ 76] = ROL(key->rk[ 70] + delta[0][16], 13);
		key->rk[ 82] = ROL(key->rk[ 76] + delta[1][17], 13);
		key->rk[ 88] = ROL(key->rk[ 82] + delta[2][18], 13);
		key->rk[ 94] = ROL(key->rk[ 88] + delta[3][19], 13);
		key->rk[100] = ROL(key->rk[ 94] + delta[4][20], 13);
		key->rk[106] = ROL(key->rk[100] + delta[5][21], 13);
		key->rk[112] = ROL(key->rk[106] + delta[0][22], 13);
		key->rk[118] = ROL(key->rk[112] + delta[1][23], 13);
		key->rk[124] = ROL(key->rk[118] + delta[2][24], 13);
		key->rk[130] = ROL(key->rk[124] + delta[3][25], 13);
		key->rk[136] = ROL(key->rk[130] + delta[4][26], 13);
		key->rk[142] = ROL(key->rk[136] + delta[5][27], 13);
		key->rk[148] = ROL(key->rk[142] + delta[0][28], 13);
		key->rk[154] = ROL(key->rk[148] + delta[1][29], 13);
		key->rk[160] = ROL(key->rk[154] + delta[2][30], 13);
		key->rk[166] = ROL(key->rk[160] + delta[3][31], 13);

#ifndef LEA_BIG_ENDIAN
		key->rk[  5] = ROL(*((unsigned int *)pbKey + 5) + delta[0][ 5], 17);
#else
		key->rk[  5] = ROL(bswap32(*((unsigned int *)pbKey + 5)) + delta[0][ 5], 17);	
#endif		
		key->rk[ 11] = ROL(key->rk[  5] + delta[1][ 6], 17);
		key->rk[ 17] = ROL(key->rk[ 11] + delta[2][ 7], 17);
		key->rk[ 23] = ROL(key->rk[ 17] + delta[3][ 8], 17);
		key->rk[ 29] = ROL(key->rk[ 23] + delta[4][ 9], 17);
		key->rk[ 35] = ROL(key->rk[ 29] + delta[5][10], 17);
		key->rk[ 41] = ROL(key->rk[ 35] + delta[0][11], 17);
		key->rk[ 47] = ROL(key->rk[ 41] + delta[1][12], 17);
		key->rk[ 53] = ROL(key->rk[ 47] + delta[2][13], 17);
		key->rk[ 59] = ROL(key->rk[ 53] + delta[3][14], 17);
		key->rk[ 65] = ROL(key->rk[ 59] + delta[4][15], 17);
		key->rk[ 71] = ROL(key->rk[ 65] + delta[5][16], 17);
		key->rk[ 77] = ROL(key->rk[ 71] + delta[0][17], 17);
		key->rk[ 83] = ROL(key->rk[ 77] + delta[1][18], 17);
		key->rk[ 89] = ROL(key->rk[ 83] + delta[2][19], 17);
		key->rk[ 95] = ROL(key->rk[ 89] + delta[3][20], 17);
		key->rk[101] = ROL(key->rk[ 95] + delta[4][21], 17);
		key->rk[107] = ROL(key->rk[101] + delta[5][22], 17);
		key->rk[113] = ROL(key->rk[107] + delta[0][23], 17);
		key->rk[119] = ROL(key->rk[113] + delta[1][24], 17);
		key->rk[125] = ROL(key->rk[119] + delta[2][25], 17);
		key->rk[131] = ROL(key->rk[125] + delta[3][26], 17);
		key->rk[137] = ROL(key->rk[131] + delta[4][27], 17);
		key->rk[143] = ROL(key->rk[137] + delta[5][28], 17);
		key->rk[149] = ROL(key->rk[143] + delta[0][29], 17);
		key->rk[155] = ROL(key->rk[149] + delta[1][30], 17);
		key->rk[161] = ROL(key->rk[155] + delta[2][31], 17);
		key->rk[167] = ROL(key->rk[161] + delta[3][ 0], 17);
		break;

	case 32:	
#ifndef LEA_BIG_ENDIAN
		key->rk[  0] = ROL(*((unsigned int *)pbKey    ) + delta[0][ 0],  1);
#else
		key->rk[  0] = ROL(bswap32(*((unsigned int *)pbKey    )) + delta[0][ 0],  1);
#endif			
		key->rk[  8] = ROL(key->rk[  0] + delta[1][ 3],  6);
		key->rk[ 16] = ROL(key->rk[  8] + delta[2][ 6], 13);
		key->rk[ 24] = ROL(key->rk[ 16] + delta[4][ 4],  1);
		key->rk[ 32] = ROL(key->rk[ 24] + delta[5][ 7],  6);
		key->rk[ 40] = ROL(key->rk[ 32] + delta[6][10], 13);
		key->rk[ 48] = ROL(key->rk[ 40] + delta[0][ 8],  1);
		key->rk[ 56] = ROL(key->rk[ 48] + delta[1][11],  6);
		key->rk[ 64] = ROL(key->rk[ 56] + delta[2][14], 13);
		key->rk[ 72] = ROL(key->rk[ 64] + delta[4][12],  1);
		key->rk[ 80] = ROL(key->rk[ 72] + delta[5][15],  6);
		key->rk[ 88] = ROL(key->rk[ 80] + delta[6][18], 13);
		key->rk[ 96] = ROL(key->rk[ 88] + delta[0][16],  1);
		key->rk[104] = ROL(key->rk[ 96] + delta[1][19],  6);
		key->rk[112] = ROL(key->rk[104] + delta[2][22], 13);
		key->rk[120] = ROL(key->rk[112] + delta[4][20],  1);
		key->rk[128] = ROL(key->rk[120] + delta[5][23],  6);
		key->rk[136] = ROL(key->rk[128] + delta[6][26], 13);
		key->rk[144] = ROL(key->rk[136] + delta[0][24],  1);
		key->rk[152] = ROL(key->rk[144] + delta[1][27],  6);
		key->rk[160] = ROL(key->rk[152] + delta[2][30], 13);
		key->rk[168] = ROL(key->rk[160] + delta[4][28],  1);
		key->rk[176] = ROL(key->rk[168] + delta[5][31],  6);
		key->rk[184] = ROL(key->rk[176] + delta[6][ 2], 13);
	
#ifndef LEA_BIG_ENDIAN
		key->rk[  1] = ROL(*((unsigned int *)pbKey + 1) + delta[0][ 1],  3);
#else
		key->rk[  1] = ROL(bswap32(*((unsigned int *)pbKey + 1)) + delta[0][ 1],  3);
#endif			
		key->rk[  9] = ROL(key->rk[  1] + delta[1][ 4], 11);
		key->rk[ 17] = ROL(key->rk[  9] + delta[2][ 7], 17);
		key->rk[ 25] = ROL(key->rk[ 17] + delta[4][ 5],  3);
		key->rk[ 33] = ROL(key->rk[ 25] + delta[5][ 8], 11);
		key->rk[ 41] = ROL(key->rk[ 33] + delta[6][11], 17);
		key->rk[ 49] = ROL(key->rk[ 41] + delta[0][ 9],  3);
		key->rk[ 57] = ROL(key->rk[ 49] + delta[1][12], 11);
		key->rk[ 65] = ROL(key->rk[ 57] + delta[2][15], 17);
		key->rk[ 73] = ROL(key->rk[ 65] + delta[4][13],  3);
		key->rk[ 81] = ROL(key->rk[ 73] + delta[5][16], 11);
		key->rk[ 89] = ROL(key->rk[ 81] + delta[6][19], 17);
		key->rk[ 97] = ROL(key->rk[ 89] + delta[0][17],  3);
		key->rk[105] = ROL(key->rk[ 97] + delta[1][20], 11);
		key->rk[113] = ROL(key->rk[105] + delta[2][23], 17);
		key->rk[121] = ROL(key->rk[113] + delta[4][21],  3);
		key->rk[129] = ROL(key->rk[121] + delta[5][24], 11);
		key->rk[137] = ROL(key->rk[129] + delta[6][27], 17);
		key->rk[145] = ROL(key->rk[137] + delta[0][25],  3);
		key->rk[153] = ROL(key->rk[145] + delta[1][28], 11);
		key->rk[161] = ROL(key->rk[153] + delta[2][31], 17);
		key->rk[169] = ROL(key->rk[161] + delta[4][29],  3);
		key->rk[177] = ROL(key->rk[169] + delta[5][ 0], 11);
		key->rk[185] = ROL(key->rk[177] + delta[6][ 3], 17);

#ifndef LEA_BIG_ENDIAN
		key->rk[  2] = ROL(*((unsigned int *)pbKey + 2) + delta[0][ 2],  6);
#else
		key->rk[  2] = ROL(bswap32(*((unsigned int *)pbKey + 2)) + delta[0][ 2],  6);
#endif		
		key->rk[ 10] = ROL(key->rk[  2] + delta[1][ 5], 13);
		key->rk[ 18] = ROL(key->rk[ 10] + delta[3][ 3],  1);
		key->rk[ 26] = ROL(key->rk[ 18] + delta[4][ 6],  6);
		key->rk[ 34] = ROL(key->rk[ 26] + delta[5][ 9], 13);
		key->rk[ 42] = ROL(key->rk[ 34] + delta[7][ 7],  1);
		key->rk[ 50] = ROL(key->rk[ 42] + delta[0][10],  6);
		key->rk[ 58] = ROL(key->rk[ 50] + delta[1][13], 13);
		key->rk[ 66] = ROL(key->rk[ 58] + delta[3][11],  1);
		key->rk[ 74] = ROL(key->rk[ 66] + delta[4][14],  6);
		key->rk[ 82] = ROL(key->rk[ 74] + delta[5][17], 13);
		key->rk[ 90] = ROL(key->rk[ 82] + delta[7][15],  1);
		key->rk[ 98] = ROL(key->rk[ 90] + delta[0][18],  6);
		key->rk[106] = ROL(key->rk[ 98] + delta[1][21], 13);
		key->rk[114] = ROL(key->rk[106] + delta[3][19],  1);
		key->rk[122] = ROL(key->rk[114] + delta[4][22],  6);
		key->rk[130] = ROL(key->rk[122] + delta[5][25], 13);
		key->rk[138] = ROL(key->rk[130] + delta[7][23],  1);
		key->rk[146] = ROL(key->rk[138] + delta[0][26],  6);
		key->rk[154] = ROL(key->rk[146] + delta[1][29], 13);
		key->rk[162] = ROL(key->rk[154] + delta[3][27],  1);
		key->rk[170] = ROL(key->rk[162] + delta[4][30],  6);
		key->rk[178] = ROL(key->rk[170] + delta[5][ 1], 13);
		key->rk[186] = ROL(key->rk[178] + delta[7][31],  1);

#ifndef LEA_BIG_ENDIAN
		key->rk[  3] = ROL(*((unsigned int *)pbKey + 3) + delta[0][ 3], 11);
#else
		key->rk[  3] = ROL(bswap32(*((unsigned int *)pbKey + 3)) + delta[0][ 3], 11);	
#endif		
		key->rk[ 11] = ROL(key->rk[  3] + delta[1][ 6], 17);
		key->rk[ 19] = ROL(key->rk[ 11] + delta[3][ 4],  3);
		key->rk[ 27] = ROL(key->rk[ 19] + delta[4][ 7], 11);
		key->rk[ 35] = ROL(key->rk[ 27] + delta[5][10], 17);
		key->rk[ 43] = ROL(key->rk[ 35] + delta[7][ 8],  3);
		key->rk[ 51] = ROL(key->rk[ 43] + delta[0][11], 11);
		key->rk[ 59] = ROL(key->rk[ 51] + delta[1][14], 17);
		key->rk[ 67] = ROL(key->rk[ 59] + delta[3][12],  3);
		key->rk[ 75] = ROL(key->rk[ 67] + delta[4][15], 11);
		key->rk[ 83] = ROL(key->rk[ 75] + delta[5][18], 17);
		key->rk[ 91] = ROL(key->rk[ 83] + delta[7][16],  3);
		key->rk[ 99] = ROL(key->rk[ 91] + delta[0][19], 11);
		key->rk[107] = ROL(key->rk[ 99] + delta[1][22], 17);
		key->rk[115] = ROL(key->rk[107] + delta[3][20],  3);
		key->rk[123] = ROL(key->rk[115] + delta[4][23], 11);
		key->rk[131] = ROL(key->rk[123] + delta[5][26], 17);
		key->rk[139] = ROL(key->rk[131] + delta[7][24],  3);
		key->rk[147] = ROL(key->rk[139] + delta[0][27], 11);
		key->rk[155] = ROL(key->rk[147] + delta[1][30], 17);
		key->rk[163] = ROL(key->rk[155] + delta[3][28],  3);
		key->rk[171] = ROL(key->rk[163] + delta[4][31], 11);
		key->rk[179] = ROL(key->rk[171] + delta[5][ 2], 17);
		key->rk[187] = ROL(key->rk[179] + delta[7][ 0],  3);

#ifndef LEA_BIG_ENDIAN
		key->rk[  4] = ROL(*((unsigned int *)pbKey + 4) + delta[0][ 4], 13);
#else
		key->rk[  4] = ROL(bswap32(*((unsigned int *)pbKey + 4)) + delta[0][ 4], 13);	
#endif		
		key->rk[ 12] = ROL(key->rk[  4] + delta[2][ 2],  1);
		key->rk[ 20] = ROL(key->rk[ 12] + delta[3][ 5],  6);
		key->rk[ 28] = ROL(key->rk[ 20] + delta[4][ 8], 13);
		key->rk[ 36] = ROL(key->rk[ 28] + delta[6][ 6],  1);
		key->rk[ 44] = ROL(key->rk[ 36] + delta[7][ 9],  6);
		key->rk[ 52] = ROL(key->rk[ 44] + delta[0][12], 13);
		key->rk[ 60] = ROL(key->rk[ 52] + delta[2][10],  1);
		key->rk[ 68] = ROL(key->rk[ 60] + delta[3][13],  6);
		key->rk[ 76] = ROL(key->rk[ 68] + delta[4][16], 13);
		key->rk[ 84] = ROL(key->rk[ 76] + delta[6][14],  1);
		key->rk[ 92] = ROL(key->rk[ 84] + delta[7][17],  6);
		key->rk[100] = ROL(key->rk[ 92] + delta[0][20], 13);
		key->rk[108] = ROL(key->rk[100] + delta[2][18],  1);
		key->rk[116] = ROL(key->rk[108] + delta[3][21],  6);
		key->rk[124] = ROL(key->rk[116] + delta[4][24], 13);
		key->rk[132] = ROL(key->rk[124] + delta[6][22],  1);
		key->rk[140] = ROL(key->rk[132] + delta[7][25],  6);
		key->rk[148] = ROL(key->rk[140] + delta[0][28], 13);
		key->rk[156] = ROL(key->rk[148] + delta[2][26],  1);
		key->rk[164] = ROL(key->rk[156] + delta[3][29],  6);
		key->rk[172] = ROL(key->rk[164] + delta[4][ 0], 13);
		key->rk[180] = ROL(key->rk[172] + delta[6][30],  1);
		key->rk[188] = ROL(key->rk[180] + delta[7][ 1],  6);

#ifndef LEA_BIG_ENDIAN
		key->rk[  5] = ROL(*((unsigned int *)pbKey + 5) + delta[0][ 5], 17);
#else
		key->rk[  5] = ROL(bswap32(*((unsigned int *)pbKey + 5)) + delta[0][ 5], 17);	
#endif			
		key->rk[ 13] = ROL(key->rk[  5] + delta[2][ 3],  3);
		key->rk[ 21] = ROL(key->rk[ 13] + delta[3][ 6], 11);
		key->rk[ 29] = ROL(key->rk[ 21] + delta[4][ 9], 17);
		key->rk[ 37] = ROL(key->rk[ 29] + delta[6][ 7],  3);
		key->rk[ 45] = ROL(key->rk[ 37] + delta[7][10], 11);
		key->rk[ 53] = ROL(key->rk[ 45] + delta[0][13], 17);
		key->rk[ 61] = ROL(key->rk[ 53] + delta[2][11],  3);
		key->rk[ 69] = ROL(key->rk[ 61] + delta[3][14], 11);
		key->rk[ 77] = ROL(key->rk[ 69] + delta[4][17], 17);
		key->rk[ 85] = ROL(key->rk[ 77] + delta[6][15],  3);
		key->rk[ 93] = ROL(key->rk[ 85] + delta[7][18], 11);
		key->rk[101] = ROL(key->rk[ 93] + delta[0][21], 17);
		key->rk[109] = ROL(key->rk[101] + delta[2][19],  3);
		key->rk[117] = ROL(key->rk[109] + delta[3][22], 11);
		key->rk[125] = ROL(key->rk[117] + delta[4][25], 17);
		key->rk[133] = ROL(key->rk[125] + delta[6][23],  3);
		key->rk[141] = ROL(key->rk[133] + delta[7][26], 11);
		key->rk[149] = ROL(key->rk[141] + delta[0][29], 17);
		key->rk[157] = ROL(key->rk[149] + delta[2][27],  3);
		key->rk[165] = ROL(key->rk[157] + delta[3][30], 11);
		key->rk[173] = ROL(key->rk[165] + delta[4][ 1], 17);
		key->rk[181] = ROL(key->rk[173] + delta[6][31],  3);
		key->rk[189] = ROL(key->rk[181] + delta[7][ 2], 11);
	
#ifndef LEA_BIG_ENDIAN
		key->rk[  6] = ROL(*((unsigned int *)pbKey + 6) + delta[1][ 1],  1);
#else
		key->rk[  6] = ROL(bswap32(*((unsigned int *)pbKey + 6)) + delta[1][ 1],  1);
#endif
		key->rk[ 14] = ROL(key->rk[  6] + delta[2][ 4],  6);
		key->rk[ 22] = ROL(key->rk[ 14] + delta[3][ 7], 13);
		key->rk[ 30] = ROL(key->rk[ 22] + delta[5][ 5],  1);
		key->rk[ 38] = ROL(key->rk[ 30] + delta[6][ 8],  6);
		key->rk[ 46] = ROL(key->rk[ 38] + delta[7][11], 13);
		key->rk[ 54] = ROL(key->rk[ 46] + delta[1][ 9],  1);
		key->rk[ 62] = ROL(key->rk[ 54] + delta[2][12],  6);
		key->rk[ 70] = ROL(key->rk[ 62] + delta[3][15], 13);
		key->rk[ 78] = ROL(key->rk[ 70] + delta[5][13],  1);
		key->rk[ 86] = ROL(key->rk[ 78] + delta[6][16],  6);
		key->rk[ 94] = ROL(key->rk[ 86] + delta[7][19], 13);
		key->rk[102] = ROL(key->rk[ 94] + delta[1][17],  1);
		key->rk[110] = ROL(key->rk[102] + delta[2][20],  6);
		key->rk[118] = ROL(key->rk[110] + delta[3][23], 13);
		key->rk[126] = ROL(key->rk[118] + delta[5][21],  1);
		key->rk[134] = ROL(key->rk[126] + delta[6][24],  6);
		key->rk[142] = ROL(key->rk[134] + delta[7][27], 13);
		key->rk[150] = ROL(key->rk[142] + delta[1][25],  1);
		key->rk[158] = ROL(key->rk[150] + delta[2][28],  6);
		key->rk[166] = ROL(key->rk[158] + delta[3][31], 13);
		key->rk[174] = ROL(key->rk[166] + delta[5][29],  1);
		key->rk[182] = ROL(key->rk[174] + delta[6][ 0],  6);
		key->rk[190] = ROL(key->rk[182] + delta[7][ 3], 13);

#ifndef LEA_BIG_ENDIAN
		key->rk[  7] = ROL(*((unsigned int *)pbKey + 7) + delta[1][ 2],  3);
#else
		key->rk[  7] = ROL(bswap32(*((unsigned int *)pbKey + 7)) + delta[1][ 2],  3);	
#endif		
		key->rk[ 15] = ROL(key->rk[  7] + delta[2][ 5], 11);
		key->rk[ 23] = ROL(key->rk[ 15] + delta[3][ 8], 17);
		key->rk[ 31] = ROL(key->rk[ 23] + delta[5][ 6],  3);
		key->rk[ 39] = ROL(key->rk[ 31] + delta[6][ 9], 11);
		key->rk[ 47] = ROL(key->rk[ 39] + delta[7][12], 17);
		key->rk[ 55] = ROL(key->rk[ 47] + delta[1][10],  3);
		key->rk[ 63] = ROL(key->rk[ 55] + delta[2][13], 11);
		key->rk[ 71] = ROL(key->rk[ 63] + delta[3][16], 17);
		key->rk[ 79] = ROL(key->rk[ 71] + delta[5][14],  3);
		key->rk[ 87] = ROL(key->rk[ 79] + delta[6][17], 11);
		key->rk[ 95] = ROL(key->rk[ 87] + delta[7][20], 17);
		key->rk[103] = ROL(key->rk[ 95] + delta[1][18],  3);
		key->rk[111] = ROL(key->rk[103] + delta[2][21], 11);
		key->rk[119] = ROL(key->rk[111] + delta[3][24], 17);
		key->rk[127] = ROL(key->rk[119] + delta[5][22],  3);
		key->rk[135] = ROL(key->rk[127] + delta[6][25], 11);
		key->rk[143] = ROL(key->rk[135] + delta[7][28], 17);
		key->rk[151] = ROL(key->rk[143] + delta[1][26],  3);
		key->rk[159] = ROL(key->rk[151] + delta[2][29], 11);
		key->rk[167] = ROL(key->rk[159] + delta[3][ 0], 17);
		key->rk[175] = ROL(key->rk[167] + delta[5][30],  3);
		key->rk[183] = ROL(key->rk[175] + delta[6][ 1], 11);
		key->rk[191] = ROL(key->rk[183] + delta[7][ 4], 17);
		break;

	default:
		return -2;
	}

	key->round = (nKeyLen >> 1) + 16;
#ifdef _LEA_DEBUG
	printf("__ENDIAN__ : [%s]\n", __ENDIAN__);
	for (i=0; i<key->round; i++)
	{
		printf("RndKey[%2d]: ", i);
		ShowWord(key->rk + (i*6), 6);
	}
#endif
	return 0;
}

/*	
	Name : S_LEA_Encrypt
	Description: LEA 블럭 암호화
	Parameters
	[in] key : 키 구조체	 
	[in] in : 암호화 할 데이터	( bytes )
	[out] out : 암호화 된 데이터 ( bytes )
	Return Value : 성공일 경우 0, 실패일 경우 -1, -2 값
	Note : key는 S_LEA_Keyschedule 호출 결과로 얻은 LEA 키설정 구조체
*/
int S_LEA_Encrypt(LEA_KEY *key, const U8 *in, U8 *out)
{
	unsigned int X0,X1,X2,X3;

	if( !key ) return -1;

	ctow(in     , &X0);
	ctow(in +  4, &X1);
	ctow(in +  8, &X2);
	ctow(in + 12, &X3);

#ifdef _LEA_DEBUG
	printf("\nX[%2d] : %08X %08X %08X %08X\n", 0, X0, X1, X2, X3);
#endif

	X3 = ROR((X2 ^ key->rk[  4]) + (X3 ^ key->rk[  5]), 3);
	X2 = ROR((X1 ^ key->rk[  2]) + (X2 ^ key->rk[  3]), 5);
	X1 = ROL((X0 ^ key->rk[  0]) + (X1 ^ key->rk[  1]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 1, X1, X2, X3, X0);
#endif
	X0 = ROR((X3 ^ key->rk[ 10]) + (X0 ^ key->rk[ 11]), 3);
	X3 = ROR((X2 ^ key->rk[  8]) + (X3 ^ key->rk[  9]), 5);
	X2 = ROL((X1 ^ key->rk[  6]) + (X2 ^ key->rk[  7]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 2, X2, X3, X0, X1);
#endif
	X1 = ROR((X0 ^ key->rk[ 16]) + (X1 ^ key->rk[ 17]), 3);
	X0 = ROR((X3 ^ key->rk[ 14]) + (X0 ^ key->rk[ 15]), 5);
	X3 = ROL((X2 ^ key->rk[ 12]) + (X3 ^ key->rk[ 13]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 3, X3, X0, X1, X2);
#endif
	X2 = ROR((X1 ^ key->rk[ 22]) + (X2 ^ key->rk[ 23]), 3);
	X1 = ROR((X0 ^ key->rk[ 20]) + (X1 ^ key->rk[ 21]), 5);
	X0 = ROL((X3 ^ key->rk[ 18]) + (X0 ^ key->rk[ 19]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 4, X0, X1, X2, X3);
#endif

	X3 = ROR((X2 ^ key->rk[ 28]) + (X3 ^ key->rk[ 29]), 3);
	X2 = ROR((X1 ^ key->rk[ 26]) + (X2 ^ key->rk[ 27]), 5);
	X1 = ROL((X0 ^ key->rk[ 24]) + (X1 ^ key->rk[ 25]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 5, X1, X2, X3, X0);
#endif
	X0 = ROR((X3 ^ key->rk[ 34]) + (X0 ^ key->rk[ 35]), 3);
	X3 = ROR((X2 ^ key->rk[ 32]) + (X3 ^ key->rk[ 33]), 5);
	X2 = ROL((X1 ^ key->rk[ 30]) + (X2 ^ key->rk[ 31]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 6, X2, X3, X0, X1);
#endif
	X1 = ROR((X0 ^ key->rk[ 40]) + (X1 ^ key->rk[ 41]), 3);
	X0 = ROR((X3 ^ key->rk[ 38]) + (X0 ^ key->rk[ 39]), 5);
	X3 = ROL((X2 ^ key->rk[ 36]) + (X3 ^ key->rk[ 37]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 7, X3, X0, X1, X2);
#endif
	X2 = ROR((X1 ^ key->rk[ 46]) + (X2 ^ key->rk[ 47]), 3);
	X1 = ROR((X0 ^ key->rk[ 44]) + (X1 ^ key->rk[ 45]), 5);
	X0 = ROL((X3 ^ key->rk[ 42]) + (X0 ^ key->rk[ 43]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 8, X0, X1, X2, X3);
#endif

	X3 = ROR((X2 ^ key->rk[ 52]) + (X3 ^ key->rk[ 53]), 3);
	X2 = ROR((X1 ^ key->rk[ 50]) + (X2 ^ key->rk[ 51]), 5);
	X1 = ROL((X0 ^ key->rk[ 48]) + (X1 ^ key->rk[ 49]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 9, X1, X2, X3, X0);
#endif
	X0 = ROR((X3 ^ key->rk[ 58]) + (X0 ^ key->rk[ 59]), 3);
	X3 = ROR((X2 ^ key->rk[ 56]) + (X3 ^ key->rk[ 57]), 5);
	X2 = ROL((X1 ^ key->rk[ 54]) + (X2 ^ key->rk[ 55]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 10, X2, X3, X0, X1);
#endif
	X1 = ROR((X0 ^ key->rk[ 64]) + (X1 ^ key->rk[ 65]), 3);
	X0 = ROR((X3 ^ key->rk[ 62]) + (X0 ^ key->rk[ 63]), 5);
	X3 = ROL((X2 ^ key->rk[ 60]) + (X3 ^ key->rk[ 61]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 11, X3, X0, X1, X2);
#endif
	X2 = ROR((X1 ^ key->rk[ 70]) + (X2 ^ key->rk[ 71]), 3);
	X1 = ROR((X0 ^ key->rk[ 68]) + (X1 ^ key->rk[ 69]), 5);
	X0 = ROL((X3 ^ key->rk[ 66]) + (X0 ^ key->rk[ 67]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 12, X0, X1, X2, X3);
#endif

	X3 = ROR((X2 ^ key->rk[ 76]) + (X3 ^ key->rk[ 77]), 3);
	X2 = ROR((X1 ^ key->rk[ 74]) + (X2 ^ key->rk[ 75]), 5);
	X1 = ROL((X0 ^ key->rk[ 72]) + (X1 ^ key->rk[ 73]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 13, X1, X2, X3, X0);
#endif
	X0 = ROR((X3 ^ key->rk[ 82]) + (X0 ^ key->rk[ 83]), 3);
	X3 = ROR((X2 ^ key->rk[ 80]) + (X3 ^ key->rk[ 81]), 5);
	X2 = ROL((X1 ^ key->rk[ 78]) + (X2 ^ key->rk[ 79]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 14, X2, X3, X0, X1);
#endif
	X1 = ROR((X0 ^ key->rk[ 88]) + (X1 ^ key->rk[ 89]), 3);
	X0 = ROR((X3 ^ key->rk[ 86]) + (X0 ^ key->rk[ 87]), 5);
	X3 = ROL((X2 ^ key->rk[ 84]) + (X3 ^ key->rk[ 85]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 15, X3, X0, X1, X2);
#endif
	X2 = ROR((X1 ^ key->rk[ 94]) + (X2 ^ key->rk[ 95]), 3);
	X1 = ROR((X0 ^ key->rk[ 92]) + (X1 ^ key->rk[ 93]), 5);
	X0 = ROL((X3 ^ key->rk[ 90]) + (X0 ^ key->rk[ 91]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 16, X0, X1, X2, X3);
#endif

	X3 = ROR((X2 ^ key->rk[100]) + (X3 ^ key->rk[101]), 3);
	X2 = ROR((X1 ^ key->rk[ 98]) + (X2 ^ key->rk[ 99]), 5);
	X1 = ROL((X0 ^ key->rk[ 96]) + (X1 ^ key->rk[ 97]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 17, X1, X2, X3, X0);
#endif
	X0 = ROR((X3 ^ key->rk[106]) + (X0 ^ key->rk[107]), 3);
	X3 = ROR((X2 ^ key->rk[104]) + (X3 ^ key->rk[105]), 5);
	X2 = ROL((X1 ^ key->rk[102]) + (X2 ^ key->rk[103]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 18, X2, X3, X0, X1);
#endif
	X1 = ROR((X0 ^ key->rk[112]) + (X1 ^ key->rk[113]), 3);
	X0 = ROR((X3 ^ key->rk[110]) + (X0 ^ key->rk[111]), 5);
	X3 = ROL((X2 ^ key->rk[108]) + (X3 ^ key->rk[109]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 19, X3, X0, X1, X2);
#endif
	X2 = ROR((X1 ^ key->rk[118]) + (X2 ^ key->rk[119]), 3);
	X1 = ROR((X0 ^ key->rk[116]) + (X1 ^ key->rk[117]), 5);
	X0 = ROL((X3 ^ key->rk[114]) + (X0 ^ key->rk[115]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 20, X0, X1, X2, X3);
#endif
	
	X3 = ROR((X2 ^ key->rk[124]) + (X3 ^ key->rk[125]), 3);
	X2 = ROR((X1 ^ key->rk[122]) + (X2 ^ key->rk[123]), 5);
	X1 = ROL((X0 ^ key->rk[120]) + (X1 ^ key->rk[121]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 21, X1, X2, X3, X0);
#endif
	X0 = ROR((X3 ^ key->rk[130]) + (X0 ^ key->rk[131]), 3);
	X3 = ROR((X2 ^ key->rk[128]) + (X3 ^ key->rk[129]), 5);
	X2 = ROL((X1 ^ key->rk[126]) + (X2 ^ key->rk[127]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 22, X2, X3, X0, X1);
#endif
	X1 = ROR((X0 ^ key->rk[136]) + (X1 ^ key->rk[137]), 3);
	X0 = ROR((X3 ^ key->rk[134]) + (X0 ^ key->rk[135]), 5);
	X3 = ROL((X2 ^ key->rk[132]) + (X3 ^ key->rk[133]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 23, X3, X0, X1, X2);
#endif
	X2 = ROR((X1 ^ key->rk[142]) + (X2 ^ key->rk[143]), 3);
	X1 = ROR((X0 ^ key->rk[140]) + (X1 ^ key->rk[141]), 5);
	X0 = ROL((X3 ^ key->rk[138]) + (X0 ^ key->rk[139]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 24, X0, X1, X2, X3);
#endif

	if(key->round > 24)
	{
		X3 = ROR((X2 ^ key->rk[148]) + (X3 ^ key->rk[149]), 3);
		X2 = ROR((X1 ^ key->rk[146]) + (X2 ^ key->rk[147]), 5);
		X1 = ROL((X0 ^ key->rk[144]) + (X1 ^ key->rk[145]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 25, X1, X2, X3, X0);
#endif
		X0 = ROR((X3 ^ key->rk[154]) + (X0 ^ key->rk[155]), 3);
		X3 = ROR((X2 ^ key->rk[152]) + (X3 ^ key->rk[153]), 5);
		X2 = ROL((X1 ^ key->rk[150]) + (X2 ^ key->rk[151]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 26, X2, X3, X0, X1);
#endif
		X1 = ROR((X0 ^ key->rk[160]) + (X1 ^ key->rk[161]), 3);
		X0 = ROR((X3 ^ key->rk[158]) + (X0 ^ key->rk[159]), 5);
		X3 = ROL((X2 ^ key->rk[156]) + (X3 ^ key->rk[157]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 27, X3, X0, X1, X2);
#endif
		X2 = ROR((X1 ^ key->rk[166]) + (X2 ^ key->rk[167]), 3);
		X1 = ROR((X0 ^ key->rk[164]) + (X1 ^ key->rk[165]), 5);
		X0 = ROL((X3 ^ key->rk[162]) + (X0 ^ key->rk[163]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 28, X0, X1, X2, X3);
#endif
	}

	if(key->round > 28)
	{
		X3 = ROR((X2 ^ key->rk[172]) + (X3 ^ key->rk[173]), 3);
		X2 = ROR((X1 ^ key->rk[170]) + (X2 ^ key->rk[171]), 5);
		X1 = ROL((X0 ^ key->rk[168]) + (X1 ^ key->rk[169]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 29, X1, X2, X3, X0);
#endif
		X0 = ROR((X3 ^ key->rk[178]) + (X0 ^ key->rk[179]), 3);
		X3 = ROR((X2 ^ key->rk[176]) + (X3 ^ key->rk[177]), 5);
		X2 = ROL((X1 ^ key->rk[174]) + (X2 ^ key->rk[175]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 30, X2, X3, X0, X1);
#endif
		X1 = ROR((X0 ^ key->rk[184]) + (X1 ^ key->rk[185]), 3);
		X0 = ROR((X3 ^ key->rk[182]) + (X0 ^ key->rk[183]), 5);
		X3 = ROL((X2 ^ key->rk[180]) + (X3 ^ key->rk[181]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 31, X3, X0, X1, X2);
#endif
		X2 = ROR((X1 ^ key->rk[190]) + (X2 ^ key->rk[191]), 3);
		X1 = ROR((X0 ^ key->rk[188]) + (X1 ^ key->rk[189]), 5);
		X0 = ROL((X3 ^ key->rk[186]) + (X0 ^ key->rk[187]), 9);
#ifdef _LEA_DEBUG
	printf("X[%2d] : %08X %08X %08X %08X\n", 32, X0, X1, X2, X3);
#endif
	}

	wtoc(&X0, out     );
	wtoc(&X1, out +  4);
	wtoc(&X2, out +  8);
	wtoc(&X3, out + 12);

	return 0;
}

/*	
	Name : S_LEA_Decrypt
	Description: LEA 블럭 복호화
	Parameters
	[in] key : 키 구조체	 
	[in] in : 복호화 할 데이터	( bytes )
	[out] out : 복호화 된 데이터 ( bytes )
	Return Value : 성공일 경우 0, 실패일 경우 -1 값
	Note : key는 S_LEA_Keyschedule 호출 결과로 얻은 LEA 키설정 구조체
*/
int S_LEA_Decrypt(LEA_KEY *key, const U8 *in, U8 *out)
{
	unsigned int X0,X1,X2,X3;

	if( !key ) return -1;

	ctow(in     , &X0);
	ctow(in +  4, &X1);
	ctow(in +  8, &X2);
	ctow(in + 12, &X3);

	if(key->round > 28)
	{
		X0 = (ROR(X0, 9) - (X3 ^ key->rk[186])) ^ key->rk[187];
		X1 = (ROL(X1, 5) - (X0 ^ key->rk[188])) ^ key->rk[189];
		X2 = (ROL(X2, 3) - (X1 ^ key->rk[190])) ^ key->rk[191];
		X3 = (ROR(X3, 9) - (X2 ^ key->rk[180])) ^ key->rk[181];
		X0 = (ROL(X0, 5) - (X3 ^ key->rk[182])) ^ key->rk[183];
		X1 = (ROL(X1, 3) - (X0 ^ key->rk[184])) ^ key->rk[185];
		X2 = (ROR(X2, 9) - (X1 ^ key->rk[174])) ^ key->rk[175];
		X3 = (ROL(X3, 5) - (X2 ^ key->rk[176])) ^ key->rk[177];
		X0 = (ROL(X0, 3) - (X3 ^ key->rk[178])) ^ key->rk[179];
		X1 = (ROR(X1, 9) - (X0 ^ key->rk[168])) ^ key->rk[169];
		X2 = (ROL(X2, 5) - (X1 ^ key->rk[170])) ^ key->rk[171];
		X3 = (ROL(X3, 3) - (X2 ^ key->rk[172])) ^ key->rk[173];
	}

	if(key->round > 24)
	{
		X0 = (ROR(X0, 9) - (X3 ^ key->rk[162])) ^ key->rk[163];
		X1 = (ROL(X1, 5) - (X0 ^ key->rk[164])) ^ key->rk[165];
		X2 = (ROL(X2, 3) - (X1 ^ key->rk[166])) ^ key->rk[167];
		X3 = (ROR(X3, 9) - (X2 ^ key->rk[156])) ^ key->rk[157];
		X0 = (ROL(X0, 5) - (X3 ^ key->rk[158])) ^ key->rk[159];
		X1 = (ROL(X1, 3) - (X0 ^ key->rk[160])) ^ key->rk[161];
		X2 = (ROR(X2, 9) - (X1 ^ key->rk[150])) ^ key->rk[151];
		X3 = (ROL(X3, 5) - (X2 ^ key->rk[152])) ^ key->rk[153];
		X0 = (ROL(X0, 3) - (X3 ^ key->rk[154])) ^ key->rk[155];
		X1 = (ROR(X1, 9) - (X0 ^ key->rk[144])) ^ key->rk[145];
		X2 = (ROL(X2, 5) - (X1 ^ key->rk[146])) ^ key->rk[147];
		X3 = (ROL(X3, 3) - (X2 ^ key->rk[148])) ^ key->rk[149];
	}

	X0 = (ROR(X0, 9) - (X3 ^ key->rk[138])) ^ key->rk[139];
	X1 = (ROL(X1, 5) - (X0 ^ key->rk[140])) ^ key->rk[141];
	X2 = (ROL(X2, 3) - (X1 ^ key->rk[142])) ^ key->rk[143];
	X3 = (ROR(X3, 9) - (X2 ^ key->rk[132])) ^ key->rk[133];
	X0 = (ROL(X0, 5) - (X3 ^ key->rk[134])) ^ key->rk[135];
	X1 = (ROL(X1, 3) - (X0 ^ key->rk[136])) ^ key->rk[137];
	X2 = (ROR(X2, 9) - (X1 ^ key->rk[126])) ^ key->rk[127];
	X3 = (ROL(X3, 5) - (X2 ^ key->rk[128])) ^ key->rk[129];
	X0 = (ROL(X0, 3) - (X3 ^ key->rk[130])) ^ key->rk[131];
	X1 = (ROR(X1, 9) - (X0 ^ key->rk[120])) ^ key->rk[121];
	X2 = (ROL(X2, 5) - (X1 ^ key->rk[122])) ^ key->rk[123];
	X3 = (ROL(X3, 3) - (X2 ^ key->rk[124])) ^ key->rk[125];

	X0 = (ROR(X0, 9) - (X3 ^ key->rk[114])) ^ key->rk[115];
	X1 = (ROL(X1, 5) - (X0 ^ key->rk[116])) ^ key->rk[117];
	X2 = (ROL(X2, 3) - (X1 ^ key->rk[118])) ^ key->rk[119];
	X3 = (ROR(X3, 9) - (X2 ^ key->rk[108])) ^ key->rk[109];
	X0 = (ROL(X0, 5) - (X3 ^ key->rk[110])) ^ key->rk[111];
	X1 = (ROL(X1, 3) - (X0 ^ key->rk[112])) ^ key->rk[113];
	X2 = (ROR(X2, 9) - (X1 ^ key->rk[102])) ^ key->rk[103];
	X3 = (ROL(X3, 5) - (X2 ^ key->rk[104])) ^ key->rk[105];
	X0 = (ROL(X0, 3) - (X3 ^ key->rk[106])) ^ key->rk[107];
	X1 = (ROR(X1, 9) - (X0 ^ key->rk[ 96])) ^ key->rk[ 97];
	X2 = (ROL(X2, 5) - (X1 ^ key->rk[ 98])) ^ key->rk[ 99];
	X3 = (ROL(X3, 3) - (X2 ^ key->rk[100])) ^ key->rk[101];

	X0 = (ROR(X0, 9) - (X3 ^ key->rk[ 90])) ^ key->rk[ 91];
	X1 = (ROL(X1, 5) - (X0 ^ key->rk[ 92])) ^ key->rk[ 93];
	X2 = (ROL(X2, 3) - (X1 ^ key->rk[ 94])) ^ key->rk[ 95];
	X3 = (ROR(X3, 9) - (X2 ^ key->rk[ 84])) ^ key->rk[ 85];
	X0 = (ROL(X0, 5) - (X3 ^ key->rk[ 86])) ^ key->rk[ 87];
	X1 = (ROL(X1, 3) - (X0 ^ key->rk[ 88])) ^ key->rk[ 89];
	X2 = (ROR(X2, 9) - (X1 ^ key->rk[ 78])) ^ key->rk[ 79];
	X3 = (ROL(X3, 5) - (X2 ^ key->rk[ 80])) ^ key->rk[ 81];
	X0 = (ROL(X0, 3) - (X3 ^ key->rk[ 82])) ^ key->rk[ 83];
	X1 = (ROR(X1, 9) - (X0 ^ key->rk[ 72])) ^ key->rk[ 73];
	X2 = (ROL(X2, 5) - (X1 ^ key->rk[ 74])) ^ key->rk[ 75];
	X3 = (ROL(X3, 3) - (X2 ^ key->rk[ 76])) ^ key->rk[ 77];

	X0 = (ROR(X0, 9) - (X3 ^ key->rk[ 66])) ^ key->rk[ 67];
	X1 = (ROL(X1, 5) - (X0 ^ key->rk[ 68])) ^ key->rk[ 69];
	X2 = (ROL(X2, 3) - (X1 ^ key->rk[ 70])) ^ key->rk[ 71];
	X3 = (ROR(X3, 9) - (X2 ^ key->rk[ 60])) ^ key->rk[ 61];
	X0 = (ROL(X0, 5) - (X3 ^ key->rk[ 62])) ^ key->rk[ 63];
	X1 = (ROL(X1, 3) - (X0 ^ key->rk[ 64])) ^ key->rk[ 65];
	X2 = (ROR(X2, 9) - (X1 ^ key->rk[ 54])) ^ key->rk[ 55];
	X3 = (ROL(X3, 5) - (X2 ^ key->rk[ 56])) ^ key->rk[ 57];
	X0 = (ROL(X0, 3) - (X3 ^ key->rk[ 58])) ^ key->rk[ 59];
	X1 = (ROR(X1, 9) - (X0 ^ key->rk[ 48])) ^ key->rk[ 49];
	X2 = (ROL(X2, 5) - (X1 ^ key->rk[ 50])) ^ key->rk[ 51];
	X3 = (ROL(X3, 3) - (X2 ^ key->rk[ 52])) ^ key->rk[ 53];

	X0 = (ROR(X0, 9) - (X3 ^ key->rk[ 42])) ^ key->rk[ 43];
	X1 = (ROL(X1, 5) - (X0 ^ key->rk[ 44])) ^ key->rk[ 45];
	X2 = (ROL(X2, 3) - (X1 ^ key->rk[ 46])) ^ key->rk[ 47];
	X3 = (ROR(X3, 9) - (X2 ^ key->rk[ 36])) ^ key->rk[ 37];
	X0 = (ROL(X0, 5) - (X3 ^ key->rk[ 38])) ^ key->rk[ 39];
	X1 = (ROL(X1, 3) - (X0 ^ key->rk[ 40])) ^ key->rk[ 41];
	X2 = (ROR(X2, 9) - (X1 ^ key->rk[ 30])) ^ key->rk[ 31];
	X3 = (ROL(X3, 5) - (X2 ^ key->rk[ 32])) ^ key->rk[ 33];
	X0 = (ROL(X0, 3) - (X3 ^ key->rk[ 34])) ^ key->rk[ 35];
	X1 = (ROR(X1, 9) - (X0 ^ key->rk[ 24])) ^ key->rk[ 25];
	X2 = (ROL(X2, 5) - (X1 ^ key->rk[ 26])) ^ key->rk[ 27];
	X3 = (ROL(X3, 3) - (X2 ^ key->rk[ 28])) ^ key->rk[ 29];

	X0 = (ROR(X0, 9) - (X3 ^ key->rk[ 18])) ^ key->rk[ 19];
	X1 = (ROL(X1, 5) - (X0 ^ key->rk[ 20])) ^ key->rk[ 21];
	X2 = (ROL(X2, 3) - (X1 ^ key->rk[ 22])) ^ key->rk[ 23];
	X3 = (ROR(X3, 9) - (X2 ^ key->rk[ 12])) ^ key->rk[ 13];
	X0 = (ROL(X0, 5) - (X3 ^ key->rk[ 14])) ^ key->rk[ 15];
	X1 = (ROL(X1, 3) - (X0 ^ key->rk[ 16])) ^ key->rk[ 17];
	X2 = (ROR(X2, 9) - (X1 ^ key->rk[  6])) ^ key->rk[  7];
	X3 = (ROL(X3, 5) - (X2 ^ key->rk[  8])) ^ key->rk[  9];
	X0 = (ROL(X0, 3) - (X3 ^ key->rk[ 10])) ^ key->rk[ 11];
	X1 = (ROR(X1, 9) - (X0 ^ key->rk[  0])) ^ key->rk[  1];
	X2 = (ROL(X2, 5) - (X1 ^ key->rk[  2])) ^ key->rk[  3];
	X3 = (ROL(X3, 3) - (X2 ^ key->rk[  4])) ^ key->rk[  5];

	wtoc(&X0, out     );
	wtoc(&X1, out +  4);
	wtoc(&X2, out +  8);
	wtoc(&X3, out + 12);

	return 0;
}

#endif