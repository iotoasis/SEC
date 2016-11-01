
/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     digest.c  functions for Hash.

	 Creadted by DEV3

************************************************/ 
#include "../include/scrt.h"
#include <stdio.h>
#include <string.h>

/* 해쉬 돌리기 전 세팅 */
/*	
	Name : SCRT_DigestInit
	Description : 해쉬 돌리기 전 설정
	Parameters
	[in/out] ctx : 해시 알고리즘 정보를 담은 구조체
	[in] type : ctx->digest의 정보를 담은 구조체
	Note :
*/
void SCRT_DigestInit(SCRT_MD_CTX *ctx, const SCRT_MD *type)
{
	SRESULT E_SR ;
	E_SR = S_FAILED | SL_HASH | SF_SCRT_DIGEST_INIT ;

	ctx->digest=type;
	type->init(&(ctx->md));
}

/* 해쉬함수 수행 */
/*	
	Name : SCRT_DigestUpdate
	Description : 해쉬함수 수행
	Parameters
	[in/out] ctx : 해시 알고리즘 정보를 담은 구조체
	[in] data : 해시하고자 하는 데이터
	[in] count : 해시하고자 하는 데이터 길이
	Note :
*/
void SCRT_DigestUpdate(SCRT_MD_CTX *ctx, const void *data, unsigned int count)
{
	SRESULT E_SR ;
	E_SR = S_FAILED | SL_HASH | SF_SCRT_DIGEST_UPDATE ;

	ctx->digest->update(&(ctx->md.base[0]),data,(unsigned long)count);
}

/* 해쉬 함수 끝난 후 마무리 */
/*	
	Name : SCRT_DigestFinal
	Description : 해쉬 함수 끝난 후 마무리
	Parameters
	[in] ctx : 해시 알고리즘 정보를 담은 구조체
	[in/out] md : 해시된 결과값
	[in/out] size :  해시된 결과값 길이
	Note :
*/
void SCRT_DigestFinal(SCRT_MD_CTX *ctx, unsigned char *md, unsigned int *size)
{
	SRESULT E_SR ;
	E_SR = S_FAILED | SL_HASH | SF_SCRT_DIGEST_FINAL ;

	ctx->digest->final(&(ctx->md.base[0]),md);
	if (size != NULL)
		*size=ctx->digest->md_size;
	memset(&(ctx->md),0,sizeof(ctx->md));
}


/* init, update, final 한꺼번에 수행 */
/*	
	Name : SCRT_Digest
	Description : init, update, final 한꺼번에 수행
	Parameters
	[in] ctx : 해시 알고리즘 정보를 담은 구조체
	[in] in : 해시하고자 하는 원문
	[in] inl : 해시하고자 하는 원문 길이
	[in] out : 	해시된 결과값			
	[in] outl : 해시된 결과값의 길이
	Note :
*/
SRESULT	SCRT_Digest(SCRT_MD_CTX *ctx, const void *in, unsigned int inl, unsigned char *out, unsigned int *outl)
{
	
	SRESULT E_SR ;
	E_SR = S_FAILED | SL_HASH | SF_SCRT_DIGEST ;

	SCRT_DigestInit(ctx, ctx->digest);
	SCRT_DigestUpdate(ctx, in,inl);
	SCRT_DigestFinal(ctx, out, outl);

	return S_SUCCESS;
}

/* MD_CTX를 copy */
/*	
	Name : SCRT_MD_CTX_copy
	Description : 해시알고리즘 정보를 담은 구조체 MD_CTX를 copy
	Parameters
	[in] out : 대상 구조체
	[in] in : 복사하고자 하는 해시 알고리즘 정보를 담은 구조체
	Note : 성공하면 0, 실패하면 0x00135035 리턴
*/
SRESULT SCRT_MD_CTX_copy(SCRT_MD_CTX *out, SCRT_MD_CTX *in)
{
	SRESULT E_SR;

	E_SR = S_FAILED | SL_HASH | SF_SCRT_MD_CTX_COPY ;

    if ((in == NULL) || (in->digest == NULL))
		return E_SR | SR_DIGEST_MD_CTX_EMPTY_FAILED ;
	
	memcpy((char *)out,(char *)in,in->digest->ctx_size);

	return S_SUCCESS;
}    
