/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     scrt_mac.c MAC

	 Creadted by DEV3

************************************************/ 

#include "../include/scrt.h"
#include "../include/hmac.h"
#include <stdio.h>
#include <string.h>
 
#ifndef SL_MAC
#define SL_MAC 1
#endif
/*
#ifndef WIN32
#ifdef _USE_CRYPTO_BOARD

#include <time.h>

#include <ubsec.h>
#include <ubsio.h>
#include <ubsec_lib.h>


#endif // _USE_CRYPTO_BOARD //
#endif	// WIN32 //
*/

/****************************************************************************
----scrt_hmac

	parameter : <in>	SCRT_md		: hash function type 
						key			: key...
						key_len		: key_length..
						in			: data.
						inl			: in_length..
				<out>	out			: message digest
						outl		: out length.
****************************************************************************/
/*	
	Name : SCRT_HMAC
	Description : 해시 알고리즘을 이용하여 메시지 인증 코드 값을 생성한다
	Parameters
	[in] SCRT_md : 해시 알고리즘 정보를 담은 구조체
	[in] key : 메시지 인증 시 사용될 비밀번호 데이터
	[in] key_len : 메시지 인증 시 사용될 비밀번호 데이터 길이
	[in] in : 메시지 데이터
	[in] inl : 메시지 데이터 길이
	[out] out : 메시지 인증 코드 데이터
	[out] outl : 메시지 인증 코드 데이터 길이
	Return Value : 성공하였을 경우0, 그외의 경우 0보다 작은 에러코드 값 반환
	Note :
*/
SRESULT SCRT_HMAC(const SCRT_MD *SCRT_md, const void *key, int key_len,
				  const unsigned char *in, int inl, 
				  unsigned char *out, unsigned int *outl)
{
#ifdef WIN32
	HMAC_CTX c;
	static U8 m[SCRT_MAX_MD_SIZE];

	if (out == NULL) out=m;
	S_HMAC_Init(&c,key,key_len,SCRT_md);
	S_HMAC_Update(&c,in,inl);
	S_HMAC_Final(&c,out,outl);
	S_HMAC_cleanup(&c);
#else
	HMAC_CTX c;
	static U8 m[SCRT_MAX_MD_SIZE];

	if (out == NULL) out=m;
	S_HMAC_Init(&c,key,key_len,SCRT_md);
	S_HMAC_Update(&c,in,inl);
	S_HMAC_Final(&c,out,outl);
	S_HMAC_cleanup(&c);
#endif /*WIN32*/

	return S_SUCCESS;
}

/*	
	Name : SCRT_HMAC2
	Description : 해시 알고리즘을 이용하여 메시지 인증 코드 값을 생성한다
	Parameters
	[in] SCRT_md : 해시 알고리즘 정보를 담은 구조체
	[in] key : 메시지 인증 시 사용될 비밀번호 데이터
	[in] key_len : 메시지 인증 시 사용될 비밀번호 데이터 길이
	[in] in : 메시지 데이터
	[in] inl : 메시지 데이터 길이
	[out] out : 메시지 인증 코드 데이터
	[out] outl : 메시지 인증 코드 데이터 길이
	Return Value : 성공하였을 경우0, 그외의 경우 0보다 작은 에러코드 값 반환
	Note : outl 의 길이 만큼 메시지 인증코드를 반환한다
*/
SRESULT SCRT_HMAC2(const SCRT_MD *SCRT_md, const void *key, int key_len,
				  const unsigned char *in, int inl, 
				  unsigned char *out, unsigned int outl)
{
	int ml;
	HMAC_CTX c;
	static U8 m[SCRT_MAX_MD_SIZE];

	if (out == NULL) return -1;
	S_HMAC_Init(&c,key,key_len,SCRT_md);
	S_HMAC_Update(&c,in,inl);
	S_HMAC_Final(&c,m,&ml);
	memcpy(out, m, outl);
	S_HMAC_cleanup(&c);

	return S_SUCCESS;
}


