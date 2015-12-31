
/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     m_null.c

	 Creadted by DEV3

************************************************/
#include "../include/scrt.h"
#include <stdio.h>

static void function(void)
	{
	}

static SCRT_MD null_md=
	{
	NID_undef,
	NID_undef,
	0,
	function,
	function,
	function,
	
	SCRT_PKEY_NULL_method,
	0,
	sizeof(SCRT_MD *),
	};
/*	
	Name : SCRT_md_null
	Description: 
	Parameters
	Return Value : 
	Note : 
*/
SCRT_MD *SCRT_md_null(void)
	{
	return(&null_md);
	}


