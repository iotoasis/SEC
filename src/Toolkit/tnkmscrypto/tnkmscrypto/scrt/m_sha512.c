
/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     m_sha512.c

	 Creadted by DEV3

************************************************/ 

#ifndef NO_SHA512

#include "../include/scrt.h"
#include <stdio.h>

static SCRT_MD sha512_md=
{
	NID_sha512,
	NID_sha512WithRSAEncryption,
	SHA512_DIGEST_LENGTH,
	SHA512_Init,
	SHA512_Update,
	SHA512_Final,
	SCRT_PKEY_NULL_method,
	SHA512_CBLOCK,
	sizeof(SCRT_MD *)+sizeof(SHA512_CTX)
};

SCRT_MD *SCRT_sha512(void)
{
	return(&sha512_md);
}

#endif
