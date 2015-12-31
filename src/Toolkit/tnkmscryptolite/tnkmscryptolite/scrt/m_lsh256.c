
/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     m_lsh256.c

	 Creadted by DEV3

************************************************/

#ifndef NO_LSH256

#include "../include/scrt.h"
#include <stdio.h>

/* 알고리즘의 특성에 알맞는 값들을 structure 구조에 저장 */
static SCRT_MD lsh256_md=
{
	NID_lsh256,
	NID_lsh256WithRSAEncryption,
	LSH256_DIGEST_LENGTH,
	lsh256_init,
	lsh256_update,
	lsh256_final,
	SCRT_PKEY_NULL_method,
	LSH_CBLOCK,
	sizeof(SCRT_MD *)+sizeof(LSH256_CTX)
};

/*
	Name : SCRT_lsh256
 	Description : LSH256 암호 알고리즘을 사용하기 위한 정보를 담은 구조체를 반환한다. 
 	Parameters 
 	Return Value : lsh256_md 구조체를 반환한다.
 	Note :
 */
SCRT_MD *SCRT_lsh256(void)
{
	return(&lsh256_md);
}

#endif

