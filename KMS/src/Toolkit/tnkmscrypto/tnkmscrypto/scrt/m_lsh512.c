
/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     m_lsh512.c

	 Creadted by DEV3

************************************************/ 

#ifndef NO_LSH512

#include "../include/scrt.h"
#include <stdio.h>

static SCRT_MD lsh512_md=
{
	NID_lsh512,
	NID_lsh512WithRSAEncryption,
	LSH512_DIGEST_LENGTH,
	lsh512_init,
	lsh512_update,
	lsh512_final,
	SCRT_PKEY_NULL_method,
	LSH512_CBLOCK,
	sizeof(SCRT_MD *)+sizeof(LSH512_CTX)
};

SCRT_MD *SCRT_lsh512(void)
{
	return(&lsh512_md);
}

#endif
