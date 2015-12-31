
/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     m_sha256.c

	 Creadted by DEV3

************************************************/

#ifndef NO_SHA256

#include "../include/scrt.h"
#include <stdio.h>

/* 알고리즘의 특성에 알맞는 값들을 structure 구조에 저장 */
static SCRT_MD sha256_md=
{
	NID_sha256,
	NID_sha256WithRSAEncryption,
	SHA256_DIGEST_LENGTH,
	sha256_init,
	sha256_update,
	sha256_final,
	SCRT_PKEY_NULL_method,
	SHA_CBLOCK,
	sizeof(SCRT_MD *)+sizeof(SHA256_CTX)
};

/*
	Name : SCRT_sha256
 	Description : SHA256 암호 알고리즘을 사용하기 위한 정보를 담은 구조체를 반환한다. 
 	Parameters 
 	Return Value : sha256_md 구조체를 반환한다.
 	Note :
 */
SCRT_MD *SCRT_sha256(void)
{
	return(&sha256_md);
}

#endif

