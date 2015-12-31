/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     lsh512.c

	 Creadted by DEV3

************************************************/

#ifndef NO_LSH512

#include <string.h>
#include "../include/typeconvert.h"
#include "../include/lsh512.h"

//step constants
static U64 SC512[NS512][8] = {
	{ 0x97884283c938982aULL, 0xba1fca93533e2355ULL, 0xc519a2e87aeb1c03ULL, 0x9a0fc95462af17b1ULL,
	0xfc3dda8ab019a82bULL, 0x02825d079a895407ULL, 0x79f2d0a7ee06a6f7ULL, 0xd76d15eed9fdf5feULL },
	{ 0x1fcac64d01d0c2c1ULL, 0xd9ea5de69161790fULL, 0xdebc8b6366071fc8ULL, 0xa9d91db711c6c94bULL,
	0x3a18653ac9c1d427ULL, 0x84df64a223dd5b09ULL, 0x6cc37895f4ad9e70ULL, 0x448304c8d7f3f4d5ULL },
	{ 0xea91134ed29383e0ULL, 0xc4484477f2da88e8ULL, 0x9b47eec96d26e8a6ULL, 0x82f6d4c8d89014f4ULL,
	0x527da0048b95fb61ULL, 0x644406c60138648dULL, 0x303c0e8aa24c0edcULL, 0xc787cda0cbe8ca19ULL },
	{ 0x7ba46221661764caULL, 0x0c8cbc6acd6371acULL, 0xe336b836940f8f41ULL, 0x79cb9da168a50976ULL,
	0xd01da49021915cb3ULL, 0xa84accc7399cf1f1ULL, 0x6c4a992cee5aeb0cULL, 0x4f556e6cb4b2e3e0ULL },
	{ 0x200683877d7c2f45ULL, 0x9949273830d51db8ULL, 0x19eeeecaa39ed124ULL, 0x45693f0a0dae7fefULL,
	0xedc234b1b2ee1083ULL, 0xf3179400d68ee399ULL, 0xb6e3c61b4945f778ULL, 0xa4c3db216796c42fULL },
	{ 0x268a0b04f9ab7465ULL, 0xe2705f6905f2d651ULL, 0x08ddb96e426ff53dULL, 0xaea84917bc2e6f34ULL,
	0xaff6e664a0fe9470ULL, 0x0aab94d765727d8cULL, 0x9aa9e1648f3d702eULL, 0x689efc88fe5af3d3ULL },
	{ 0xb0950ffea51fd98bULL, 0x52cfc86ef8c92833ULL, 0xe69727b0b2653245ULL, 0x56f160d3ea9da3e2ULL,
	0xa6dd4b059f93051fULL, 0xb6406c3cd7f00996ULL, 0x448b45f3ccad9ec8ULL, 0x079b8587594ec73bULL },
	{ 0x45a50ea3c4f9653bULL, 0x22983767c1f15b85ULL, 0x7dbed8631797782bULL, 0x485234be88418638ULL,
	0x842850a5329824c5ULL, 0xf6aca914c7f9a04cULL, 0xcfd139c07a4c670cULL, 0xa3210ce0a8160242ULL },
	{ 0xeab3b268be5ea080ULL, 0xbacf9f29b34ce0a7ULL, 0x3c973b7aaf0fa3a8ULL, 0x9a86f346c9c7be80ULL,
	0xac78f5d7cabcea49ULL, 0xa355bddcc199ed42ULL, 0xa10afa3ac6b373dbULL, 0xc42ded88be1844e5ULL },
	{ 0x9e661b271cff216aULL, 0x8a6ec8dd002d8861ULL, 0xd3d2b629beb34be4ULL, 0x217a3a1091863f1aULL,
	0x256ecda287a733f5ULL, 0xf9139a9e5b872fe5ULL, 0xac0535017a274f7cULL, 0xf21b7646d65d2aa9ULL },
	{ 0x048142441c208c08ULL, 0xf937a5dd2db5e9ebULL, 0xa688dfe871ff30b7ULL, 0x9bb44aa217c5593bULL,
	0x943c702a2edb291aULL, 0x0cae38f9e2b715deULL, 0xb13a367ba176cc28ULL, 0x0d91bd1d3387d49bULL },
	{ 0x85c386603cac940cULL, 0x30dd830ae39fd5e4ULL, 0x2f68c85a712fe85dULL, 0x4ffeecb9dd1e94d6ULL,
	0xd0ac9a590a0443aeULL, 0xbae732dc99ccf3eaULL, 0xeb70b21d1842f4d9ULL, 0x9f4eda50bb5c6fa8ULL },
	{ 0x4949e69ce940a091ULL, 0x0e608dee8375ba14ULL, 0x983122cba118458cULL, 0x4eeba696fbb36b25ULL,
	0x7d46f3630e47f27eULL, 0xa21a0f7666c0dea4ULL, 0x5c22cf355b37cec4ULL, 0xee292b0c17cc1847ULL },
	{ 0x9330838629e131daULL, 0x6eee7c71f92fce22ULL, 0xc953ee6cb95dd224ULL, 0x3a923d92af1e9073ULL,
	0xc43a5671563a70fbULL, 0xbc2985dd279f8346ULL, 0x7ef2049093069320ULL, 0x17543723e3e46035ULL },
	{ 0xc3b409b00b130c6dULL, 0x5d6aee6b28fdf090ULL, 0x1d425b26172ff6edULL, 0xcccfd041cdaf03adULL,
	0xfe90c7c790ab6cbfULL, 0xe5af6304c722ca02ULL, 0x70f695239999b39eULL, 0x6b8b5b07c844954cULL },
	{ 0x77bdb9bb1e1f7a30ULL, 0xc859599426ee80edULL, 0x5f9d813d4726e40aULL, 0x9ca0120f7cb2b179ULL,
	0x8f588f583c182cbdULL, 0x951267cbe9eccce7ULL, 0x678bb8bd334d520eULL, 0xf6e662d00cd9e1b7ULL },
	{ 0x357774d93d99aaa7ULL, 0x21b2edbb156f6eb5ULL, 0xfd1ebe846e0aee69ULL, 0x3cb2218c2f642b15ULL,
	0xe7e7e7945444ea4cULL, 0xa77a33b5d6b9b47cULL, 0xf34475f0809f6075ULL, 0xdd4932dce6bb99adULL },
	{ 0xacec4e16d74451dcULL, 0xd4a0a8d084de23d6ULL, 0x1bdd42f278f95866ULL, 0xeed3adbb938f4051ULL,
	0xcfcf7be8992f3733ULL, 0x21ade98c906e3123ULL, 0x37ba66711fffd668ULL, 0x267c0fc3a255478aULL },
	{ 0x993a64ee1b962e88ULL, 0x754979556301faaaULL, 0xf920356b7251be81ULL, 0xc281694f22cf923fULL,
	0x9f4b6481c8666b02ULL, 0xcf97761cfe9f5444ULL, 0xf220d7911fd63e9fULL, 0xa28bd365f79cd1b0ULL },
	{ 0xd39f5309b1c4b721ULL, 0xbec2ceb864fca51fULL, 0x1955a0ddc410407aULL, 0x43eab871f261d201ULL,
	0xeaafe64a2ed16da1ULL, 0x670d931b9df39913ULL, 0x12f868b0f614de91ULL, 0x2e5f395d946e8252ULL },
	{ 0x72f25cbb767bd8f4ULL, 0x8191871d61a1c4ddULL, 0x6ef67ea1d450ba93ULL, 0x2ea32a645433d344ULL,
	0x9a963079003f0f8bULL, 0x74a0aeb9918cac7aULL, 0x0b6119a70af36fa3ULL, 0x8d9896f202f0d480ULL },
	{ 0x654f1831f254cd66ULL, 0x1318a47f0366a25eULL, 0x65752076250b4e01ULL, 0xd1cd8eb888071772ULL,
	0x30c6a9793f4e9b25ULL, 0x154f684b1e3926eeULL, 0x6c7ac0b1fe6312aeULL, 0x262f88f4f3c5550dULL },
	{ 0xb4674a24472233cbULL, 0x2bbd23826a090071ULL, 0xda95969b30594f66ULL, 0x9f5c47408f1e8a43ULL,
	0xf77022b88de9c055ULL, 0x64b7b36957601503ULL, 0xe73b72b06175c11aULL, 0x55b87de8b91a6233ULL },
	{ 0x1bb16e6b6955ff7fULL, 0xe8e0a5ec7309719cULL, 0x702c31cb89a8b640ULL, 0xfba387cfada8cde2ULL,
	0x6792db4677aa164cULL, 0x1c6b1cc0b7751867ULL, 0x22ae2311d736dc01ULL, 0x0e3666a1d37c9588ULL },
	{ 0xcd1fd9d4bf557e9aULL, 0xc986925f7c7b0e84ULL, 0x9c5dfd55325ef6b0ULL, 0x9f2b577d5676b0ddULL,
	0xfa6e21be21c062b3ULL, 0x8787dd782c8d7f83ULL, 0xd0d134e90e12dd23ULL, 0x449d087550121d96ULL },
	{ 0xecf9ae9414d41967ULL, 0x5018f1dbf789934dULL, 0xfa5b52879155a74cULL, 0xca82d4d3cd278e7cULL,
	0x688fdfdfe22316adULL, 0x0f6555a4ba0d030aULL, 0xa2061df720f000f3ULL, 0xe1a57dc5622fb3daULL },
	{ 0xe6a842a8e8ed8153ULL, 0x690acdd3811ce09dULL, 0x55adda18e6fcf446ULL, 0x4d57a8a0f4b60b46ULL,
	0xf86fbfc20539c415ULL, 0x74bafa5ec7100d19ULL, 0xa824151810f0f495ULL, 0x8723432791e38ebbULL },
	{ 0x8eeaeb91d66ed539ULL, 0x73d8a1549dfd7e06ULL, 0x0387f2ffe3f13a9bULL, 0xa5004995aac15193ULL,
	0x682f81c73efdda0dULL, 0x2fb55925d71d268dULL, 0xcc392d2901e58a3dULL, 0xaa666ab975724a42ULL }
};

//IV for LSH-512-512
static U64 IV512[16] = {
	0xadd50f3c7f07094eULL, 0xe3f3cee8f9418a4fULL, 0xb527ecde5b3d0ae9ULL, 0x2ef6dec68076f501ULL,
	0x8cb994cae5aca216ULL, 0xfbb9eae4bba48cc7ULL, 0x650a526174725feaULL, 0x1f9a61a73f8d8085ULL,
	0xb6607378173b539bULL, 0x1bc99853b0c0b9edULL, 0xdf727fc19b182d47ULL, 0xdbef360cf893a457ULL,
	0x4981f5e570147e80ULL, 0xd00c4490ca7d3e30ULL, 0x5d73940c0e4ae1ecULL, 0x894085e2edb2d819ULL
};

//rotation amounts
static const int gamma512[8] = { 0, 16, 32, 48, 8, 24, 40, 56 };

ALIGN64 static U64 m[3][16];
ALIGN64 static U64 T[16];
ALIGN64 static U64 S[16];
ALIGN64 static U64 vl, vr;

INLINE void me64(int l, int idx1, int idx2, int idx3, int tau1, int tau2)
{
	// MsgExpansion
	m[idx1][l] = m[idx2][l] + m[idx3][tau1];
	m[idx1][l + 8] = m[idx2][l + 8] + m[idx3][tau2];
}

INLINE void step0_64(int j, int l, int idx, int gamma, int rsigma1, int rsigma2, LSH512_CTX* state)
{
	// MsgAdd
	state->cv512[l] ^= m[idx][l];
	state->cv512[l + 8] ^= m[idx][l + 8];

	// Mix
	vl = state->cv512[l];
	vr = state->cv512[l + 8];
	vl += vr;
	vl = ROL64(vl, 23);
	vl ^= SC512[j][l];
	vr += vl;
	vr = ROL64(vr, 59);
	vl += vr;
	vr = ROL64(vr, gamma);

	// WordPerm
	T[rsigma1] = vl;
	T[rsigma2] = vr;
}

INLINE void step1_64(int j, int l, int idx, int gamma, int rsigma1, int rsigma2)
{
	// MsgAdd
	S[l] ^= m[idx][l];
	S[l + 8] ^= m[idx][l + 8];

	// Mix & WordPerm
	vl = S[l];
	vr = S[l + 8];
	vl += vr;
	vl = ROL64(vl, 23);
	vl ^= SC512[j][l];
	vr += vl;
	vr = ROL64(vr, 59);
	T[rsigma1] = vl + vr;
	T[rsigma2] = ROL64(vr, gamma);

}

INLINE void step2_64(int j, int l, int idx, int gamma, int rsigma1, int rsigma2)
{
	// MsgAdd
	T[l] ^= m[idx][l];
	T[l + 8] ^= m[idx][l + 8];

	// Mix & WordPerm
	vl = T[l];
	vr = T[l + 8];
	vl += vr;
	vl = ROL64(vl, 7);
	vl ^= SC512[j][l];
	vr += vl;
	vr = ROL64(vr, 3);
	S[rsigma1] = vl + vr;
	S[rsigma2] = ROL64(vr, gamma);
}

INLINE void step1_iv_64(int j, int l, int gamma, int rsigma1, int rsigma2)
{
	// Mix
	vl = IV512[l];
	vr = IV512[l + 8];
	vl += vr;
	vl = ROL64(vl, 23);
	vl ^= SC512[j][l];
	vr += vl;
	vr = ROL64(vr, 59);
	vl += vr;
	vr = ROL64(vr, gamma);

	// WordPerm
	T[rsigma1] = vl;
	T[rsigma2] = vr;
}

INLINE void step2_iv_64(int j, int l, int gamma, int rsigma1, int rsigma2)
{
	// Mix
	vl = T[l];
	vr = T[l + 8];
	vl += vr;
	vl = ROL64(vl, 7);
	vl ^= SC512[j][l];
	vr += vl;
	vr = ROL64(vr, 3);
	vl += vr;
	vr = ROL64(vr, gamma);

	// WordPerm
	IV512[rsigma1] = vl;
	IV512[rsigma2] = vr;
}

void compress512(LSH512_CTX * state, const U8 * datablock) {

	int j, l;

	//message expansion to m[0], m[1]
	for (l = 0; l < 32; l++){
		m[0][l] = U8TO64_LE(datablock + 8 * l);
	}

	step0_64(0, 0, 0, 0, 9, 12, state);		step0_64(0, 1, 0, 16, 10, 15, state);
	step0_64(0, 2, 0, 32, 8, 14, state);	step0_64(0, 3, 0, 48, 11, 13, state);
	step0_64(0, 4, 0, 8, 1, 4, state);		step0_64(0, 5, 0, 24, 2, 7, state);
	step0_64(0, 6, 0, 40, 0, 6, state);		step0_64(0, 7, 0, 56, 3, 5, state);
	
	step2_64(1, 0, 1, 0, 9, 12);	step2_64(1, 1, 1, 16, 10, 15);
	step2_64(1, 2, 1, 32, 8, 14);	step2_64(1, 3, 1, 48, 11, 13);
	step2_64(1, 4, 1, 8, 1, 4);		step2_64(1, 5, 1, 24, 2, 7);
	step2_64(1, 6, 1, 40, 0, 6);	step2_64(1, 7, 1, 56, 3, 5);

	for (j = 2; j < NS512 - 2; j += 6)
	{
		me64(0, 2, 1, 0, 3, 11); step1_64(j, 0, 2, 0, 9, 12);		me64(1, 2, 1, 0, 2, 10); step1_64(j, 1, 2, 16, 10, 15);
		me64(2, 2, 1, 0, 0, 8); step1_64(j, 2, 2, 32, 8, 14);		me64(3, 2, 1, 0, 1, 9); step1_64(j, 3, 2, 48, 11, 13);
		me64(4, 2, 1, 0, 7, 15); step1_64(j, 4, 2, 8, 1, 4);		me64(5, 2, 1, 0, 4, 12); step1_64(j, 5, 2, 24, 2, 7);
		me64(6, 2, 1, 0, 5, 13); step1_64(j, 6, 2, 40, 0, 6);		me64(7, 2, 1, 0, 6, 14); step1_64(j, 7, 2, 56, 3, 5);

		me64(0, 0, 2, 1, 3, 11); step2_64(j + 1, 0, 0, 0, 9, 12);		me64(1, 0, 2, 1, 2, 10); step2_64(j + 1, 1, 0, 16, 10, 15);
		me64(2, 0, 2, 1, 0, 8); step2_64(j + 1, 2, 0, 32, 8, 14);		me64(3, 0, 2, 1, 1, 9); step2_64(j + 1, 3, 0, 48, 11, 13);
		me64(4, 0, 2, 1, 7, 15); step2_64(j + 1, 4, 0, 8, 1, 4);		me64(5, 0, 2, 1, 4, 12); step2_64(j + 1, 5, 0, 24, 2, 7);
		me64(6, 0, 2, 1, 5, 13); step2_64(j + 1, 6, 0, 40, 0, 6);		me64(7, 0, 2, 1, 6, 14); step2_64(j + 1, 7, 0, 56, 3, 5);

		me64(0, 1, 0, 2, 3, 11); step1_64(j + 2, 0, 1, 0, 9, 12);		me64(1, 1, 0, 2, 2, 10); step1_64(j + 2, 1, 1, 16, 10, 15);
		me64(2, 1, 0, 2, 0, 8); step1_64(j + 2, 2, 1, 32, 8, 14);		me64(3, 1, 0, 2, 1, 9); step1_64(j + 2, 3, 1, 48, 11, 13);
		me64(4, 1, 0, 2, 7, 15); step1_64(j + 2, 4, 1, 8, 1, 4);		me64(5, 1, 0, 2, 4, 12); step1_64(j + 2, 5, 1, 24, 2, 7);
		me64(6, 1, 0, 2, 5, 13); step1_64(j + 2, 6, 1, 40, 0, 6);		me64(7, 1, 0, 2, 6, 14); step1_64(j + 2, 7, 1, 56, 3, 5);

		me64(0, 2, 1, 0, 3, 11); step2_64(j + 3, 0, 2, 0, 9, 12);		me64(1, 2, 1, 0, 2, 10); step2_64(j + 3, 1, 2, 16, 10, 15);
		me64(2, 2, 1, 0, 0, 8); step2_64(j + 3, 2, 2, 32, 8, 14);		me64(3, 2, 1, 0, 1, 9); step2_64(j + 3, 3, 2, 48, 11, 13);
		me64(4, 2, 1, 0, 7, 15); step2_64(j + 3, 4, 2, 8, 1, 4);		me64(5, 2, 1, 0, 4, 12); step2_64(j + 3, 5, 2, 24, 2, 7);
		me64(6, 2, 1, 0, 5, 13); step2_64(j + 3, 6, 2, 40, 0, 6);		me64(7, 2, 1, 0, 6, 14); step2_64(j + 3, 7, 2, 56, 3, 5);

		me64(0, 0, 2, 1, 3, 11); step1_64(j + 4, 0, 0, 0, 9, 12);		me64(1, 0, 2, 1, 2, 10); step1_64(j + 4, 1, 0, 16, 10, 15);
		me64(2, 0, 2, 1, 0, 8); step1_64(j + 4, 2, 0, 32, 8, 14);		me64(3, 0, 2, 1, 1, 9); step1_64(j + 4, 3, 0, 48, 11, 13);
		me64(4, 0, 2, 1, 7, 15); step1_64(j + 4, 4, 0, 8, 1, 4);		me64(5, 0, 2, 1, 4, 12); step1_64(j + 4, 5, 0, 24, 2, 7);
		me64(6, 0, 2, 1, 5, 13); step1_64(j + 4, 6, 0, 40, 0, 6);		me64(7, 0, 2, 1, 6, 14); step1_64(j + 4, 7, 0, 56, 3, 5);

		me64(0, 1, 0, 2, 3, 11); step2_64(j + 5, 0, 1, 0, 9, 12);		me64(1, 1, 0, 2, 2, 10); step2_64(j + 5, 1, 1, 16, 10, 15);
		me64(2, 1, 0, 2, 0, 8); step2_64(j + 5, 2, 1, 32, 8, 14);		me64(3, 1, 0, 2, 1, 9); step2_64(j + 5, 3, 1, 48, 11, 13);
		me64(4, 1, 0, 2, 7, 15); step2_64(j + 5, 4, 1, 8, 1, 4);		me64(5, 1, 0, 2, 4, 12); step2_64(j + 5, 5, 1, 24, 2, 7);
		me64(6, 1, 0, 2, 5, 13); step2_64(j + 5, 6, 1, 40, 0, 6);		me64(7, 1, 0, 2, 6, 14); step2_64(j + 5, 7, 1, 56, 3, 5);

	}

	// j=26
	me64(0, 2, 1, 0, 3, 11); step1_64(26, 0, 2, 0, 9, 12);	me64(1, 2, 1, 0, 2, 10); step1_64(26, 1, 2, 16, 10, 15);
	me64(2, 2, 1, 0, 0, 8); step1_64(26, 2, 2, 32, 8, 14);	me64(3, 2, 1, 0, 1, 9); step1_64(26, 3, 2, 48, 11, 13);
	me64(4, 2, 1, 0, 7, 15); step1_64(26, 4, 2, 8, 1, 4);	me64(5, 2, 1, 0, 4, 12); step1_64(26, 5, 2, 24, 2, 7);
	me64(6, 2, 1, 0, 5, 13); step1_64(26, 6, 2, 40, 0, 6);	me64(7, 2, 1, 0, 6, 14); step1_64(26, 7, 2, 56, 3, 5);

	//j=27
	me64(0, 0, 2, 1, 3, 11); step2_64(27, 0, 0, 0, 9, 12);	me64(1, 0, 2, 1, 2, 10); step2_64(27, 1, 0, 16, 10, 15);
	me64(2, 0, 2, 1, 0, 8); step2_64(27, 2, 0, 32, 8, 14);	me64(3, 0, 2, 1, 1, 9); step2_64(27, 3, 0, 48, 11, 13);
	me64(4, 0, 2, 1, 7, 15); step2_64(27, 4, 0, 8, 1, 4);	me64(5, 0, 2, 1, 4, 12); step2_64(27, 5, 0, 24, 2, 7);
	me64(6, 0, 2, 1, 5, 13); step2_64(27, 6, 0, 40, 0, 6);	me64(7, 0, 2, 1, 6, 14); step2_64(27, 7, 0, 56, 3, 5);

	state->cv512[ 0]=S[ 0]^(m[0][ 0] + m[2][ 3]);
	state->cv512[ 8]=S[ 8]^(m[0][ 8] + m[2][11]);
	state->cv512[ 1]=S[ 1]^(m[0][ 1] + m[2][ 2]);
	state->cv512[ 9]=S[ 9]^(m[0][ 9] + m[2][10]);
	state->cv512[ 2]=S[ 2]^(m[0][ 2] + m[2][ 0]);
	state->cv512[10]=S[10]^(m[0][10] + m[2][ 8]);
	state->cv512[ 3]=S[ 3]^(m[0][ 3] + m[2][ 1]);
	state->cv512[11]=S[11]^(m[0][11] + m[2][ 9]);
	state->cv512[ 4]=S[ 4]^(m[0][ 4] + m[2][ 7]);
	state->cv512[12]=S[12]^(m[0][12] + m[2][15]);
	state->cv512[ 5]=S[ 5]^(m[0][ 5] + m[2][ 4]);
	state->cv512[13]=S[13]^(m[0][13] + m[2][12]);
	state->cv512[ 6]=S[ 6]^(m[0][ 6] + m[2][ 5]);
	state->cv512[14]=S[14]^(m[0][14] + m[2][13]);
	state->cv512[ 7]=S[ 7]^(m[0] [7] + m[2][ 6]);
	state->cv512[15]=S[15]^(m[0][15] + m[2][14]);

	return;
}

void GetIV512(int hashbitlen)
{
	int j;

	memset(IV512, 0, 16 * sizeof(U64));
	IV512[0] = 64;
	IV512[1] = (U64)hashbitlen;

	for (j = 0; j < NS512 ; j += 2)
	{
		step1_iv_64(j, 0, 0, 9, 12);
		step1_iv_64(j, 1, 16, 10, 15);
		step1_iv_64(j, 2, 32, 8, 14);
		step1_iv_64(j, 3, 48, 11, 13);
		step1_iv_64(j, 4, 8, 1, 4);
		step1_iv_64(j, 5, 24, 2, 7);
		step1_iv_64(j, 6, 40, 0, 6);
		step1_iv_64(j, 7, 56, 3, 5);

		step2_iv_64(j + 1, 0, 0, 9, 12);
		step2_iv_64(j + 1, 1, 16, 10, 15);
		step2_iv_64(j + 1, 2,  32, 8, 14);
		step2_iv_64(j + 1, 3, 48, 11, 13);
		step2_iv_64(j + 1, 4, 8,  1, 4);
		step2_iv_64(j + 1, 5, 24, 2, 7);
		step2_iv_64(j + 1, 6, 40, 0, 6);
		step2_iv_64(j + 1, 7, 56, 3, 5);
	}

	return;
}

/*	
	Name : lsh512_init
	Description: LSH512 해쉬를 위해 컨텍스트를 초기화한다.
	Parameters
	[out] ctx : 초기화할 컨텍스트 구조체
	Return Value : 
	Note : 
*/
void lsh512_init( LSH512_CTX *ctx )
{
	memcpy(ctx->cv512, IV512, sizeof(IV512));
	ctx->hashbitlen = 512;

	return ;
	/*
	if ((hashbitlen <0) || (hashbitlen>512))
		return BAD_HASHBITLEN;
	else {
		if (hashbitlen < 512) 
			GetIV512(hashbitlen);
		memcpy(state->cv512, IV512, sizeof(IV512));
	}

	state->hashbitlen = hashbitlen;

	return SUCCESS;
	*/
}

/*	
	Name : lsh512_update
	Description: 전체 데이터에 대한 중간단계 해시계산을 수행한다.
	Parameters
	[in/out] ctx : 해시계산값이 저장되는 컨텍스트 구조체
	[in] input : 해시를 수행할 전체 데이터
	[in] length : 해시를 수행할 전체 데이터 길이값
	Return Value : 
	Note : 
*/
void lsh512_update( LSH512_CTX *ctx, U8 *input, U32 length )
{
	U64 numBlocks, temp, databitlen=length*8;
	int pos1, pos2;
	int i;
	numBlocks = ((U64)databitlen >> 11) + 1;

	for (i = 0; i < numBlocks - 1; i++){
		compress512(ctx, input);
		input += 256;
	}

	//computation of the ctx->Last512 block (padding)
	//computation of the ctx->Last512 block (padded)
	//if databitlen not multiple of 2048
	//databitlen = 2048*(numBlocks-1) + 8*pos1 + pos2, 0<=pos1<256, 0<=pos2<7
	if ((U32)(databitlen)& 0x7ff){
		temp = (numBlocks - 1) << 8; //temp = 256*(numBlocks-1)
		pos1 = (U32)((databitlen >> 3) - temp);
		pos2 = (U32)(databitlen & 0x7);

		//if databitlen not multiple of 8
		if (pos2){
			memcpy(ctx->Last512, input, pos1*sizeof(char));//			
			ctx->Last512[pos1] = (input[pos1] & (0xff << (8 - pos2))) ^ (1 << (7 - pos2));
			if (pos1 != 255) memset(ctx->Last512 + pos1 + 1, 0, (255 - pos1)*sizeof(char));
		}
		//if databitlen multiple of 8
		else{
			memcpy(ctx->Last512, input, pos1*sizeof(char));
			ctx->Last512[pos1] = 0x80;
			if (pos1 != 255) memset(ctx->Last512 + pos1 + 1, 0, (255 - pos1)*sizeof(char));
		}
	}
	//if databitlen multiple of 2048
	else{
		ctx->Last512[0] = 0x80;
		memset(ctx->Last512 + 1, 0, 255 * sizeof(U8));
	}
	// end of computation of the ctx->Last512 block
	return;
}

/*	
	Name : lsh256_final
	Description: 패딩작업을 거쳐 최종단계 해시값을 생성한다.
	Parameters
	[in] ctx : 해시계산값이 저장되는 컨텍스트 구조체
	[out] digest : 512비트 해시결과값
	Return Value : 
	Note : 
*/
void lsh512_final( LSH512_CTX *ctx, U8 *digest)
{
	int l;
	static U64 H[8];

	compress512(ctx, ctx->Last512);

	for (l = 0; l < 8; l++) H[l] = (ctx->cv512[l]) ^ (ctx->cv512[l + 8]);


	for (l = 0; l < (ctx->hashbitlen) >> 3; l++){
		//		hashval[l] = (u8)(ROR64(H[l >> 3], (l << 3) & 0x3f));
		digest[l] = (U8)(H[l >> 3] >> ((l << 3) & 0x3f)); //0,8,16,24,32,40,48,56,0,... = 8*l (mod 64) = (l<<3)&0x3f
	}

	return;
}

/*	
	Name : S_LSH512
	Description: 데이터에 대한 SHA256 해시값을 계산한다.
	Parameters
	[out] out : 해시 결과값
	[in] in : 해시 대상 원문
	[in] bytes : 해시 대상 원문 길이값
	Return Value : 
	Note : 
*/
void S_LSH512(U8 *out, U8 *in, U32 bytes)
{
	LSH512_CTX ctx;
	lsh512_init(&ctx);
	lsh512_update(&ctx, in, bytes);
	lsh512_final(&ctx,out);
}

#endif