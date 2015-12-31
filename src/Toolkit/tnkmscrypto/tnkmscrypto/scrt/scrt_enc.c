
/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     scrt_enc.c

	 Creadted by DEV3

************************************************/

#include "../include/scrt.h"
#include <stdio.h>
#include <string.h>

/*	
	Name : SCRT_CIPHER_CTX_init
	Description: RSA 암/복호화에 사용될 키 구조체 설정
	Parameters
	[out] ctx : 키 구조체 값을 저장할 컨텍스트 구조체 	
	Return Value : 
	Note :
*/
void SCRT_CIPHER_CTX_init(SCRT_CIPHER_CTX *ctx)
{
	memset(ctx,0,sizeof(SCRT_CIPHER_CTX));
	ctx->cipher=NULL; 
}

/*	
	Name : SCRT_EncryptInit
	Description: 암호화에 사용될 키를 구조체에 설정한다.
	Parameters
	[out] ctx : 키 구조체 값을 저장할 컨텍스트 구조체
	[in] cipher : 대칭키 암호화 키정보를 저장한 구조체
	[in] key : 암호키 값
	[in] iv : 초기 벡터값
	Return Value : 실패시 에러코드 성공시 0
	Note :
*/
/* key schedule, iv setting for encryption */
SRESULT SCRT_EncryptInit(SCRT_CIPHER_CTX *ctx, const SCRT_CIPHER *cipher, unsigned char *key, unsigned char *iv)
{	
	SRESULT E_SR;

	E_SR = S_FAILED | SL_BLOCK | SF_SCRT_ENCRYPT_INIT;
	
	if(ctx == NULL) return E_SR | SR_BLOCK_CIPHER_CTX_EMPTY_FAILED ;

	if (cipher != NULL) 
		ctx->cipher=cipher;
	else
		return E_SR | SR_BLOCK_CIPHER_EMPTY_FAILED ;
			
	ctx->cipher->init(ctx,key,iv,1);
	ctx->encrypt=1;
	ctx->buf_len=0;

	return S_SUCCESS;
}

/*	
	Name : SCRT_DecryptInit
	Description: 복호화에 사용될 키를 구조체에 설정한다.
	Parameters
	[out] ctx : 키 구조체 값을 저장할 컨텍스트 구조체
	[in] cipher : 대칭키 암/복호화 키정보를 저장한 컨텍스트 구조체
	[in] key : 암호키 값
	[in] iv : 초기 벡터값
	Return Value : 실패시 에러코드 성공시 0
	Note
*/
/* key schedule, iv setting for decryption */
SRESULT SCRT_DecryptInit(SCRT_CIPHER_CTX *ctx, const SCRT_CIPHER *cipher, unsigned char *key, unsigned char *iv)
{
	SRESULT E_SR;

	E_SR = S_FAILED | SL_BLOCK | SF_SCRT_DECRYPT_INIT;

	if(ctx == NULL) return E_SR | SR_BLOCK_CIPHER_CTX_EMPTY_FAILED ;

	if (cipher != NULL)
		ctx->cipher=cipher;
	else
		return E_SR | SR_BLOCK_CIPHER_EMPTY_FAILED ;

	ctx->cipher->init(ctx,key,iv,0);
	ctx->encrypt=0;
	ctx->buf_len=0;

	return S_SUCCESS;

}
/*	
	Name : SCRT_EncryptUpdate
	Description: padding 제외한 부분 암호화
	Parameters
	[in/out] ctx : 암호화에 사용될 키를 저장한 컨텍스트 구조체	
	[out] out : 암호화된 값
	[out] outl : 암호화된 데이터 길이
	[in] in : 암호화할 평문데이터
	[in] inl : 암호화할 평문데이터 길이
	Return Value : 
	Note
*/
/*  padding 제외한 부분 암호화. */
SRESULT SCRT_EncryptUpdate(SCRT_CIPHER_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int inl)
{
	SRESULT E_SR;
	int i,j,bl;

	E_SR = S_FAILED | SL_BLOCK | SF_SCRT_ENCRYPT_UPDATE ;
	i=ctx->buf_len;
	bl=ctx->cipher->block_size;
	*outl=0;

	if ((inl == 0) && (i != bl))  return E_SR | SR_BLOCK_PADDING_BUFFER_LENGTH_WRONG;
	if (i != 0)
	{
		if (i+inl < bl) 
		{
			memcpy(&(ctx->buf[i]),in,inl);
			ctx->buf_len+=inl;
			return E_SR | SR_BLOCK_PADDING_BLOCK_SIZE_WRONG;
		}
		else /* 실제로..decrypt fianl에서 호출되는 부분. */
		{
			j=bl-i;
			if (j != 0) memcpy(&(ctx->buf[i]),in,j);
			ctx->cipher->do_cipher(ctx,out,ctx->buf,bl);
			inl-=j;
			in+=j;
			out+=bl;
			*outl+=bl;
		}
	}
	i=inl%bl;
	inl-=i;
	if (inl > 0)
	{
		ctx->cipher->do_cipher(ctx,out,in,inl);
		*outl+=inl;
	}

	if (i != 0)
		memcpy(ctx->buf,&(in[inl]),i);
	
	ctx->buf_len=i;
	return S_SUCCESS;
}
/*	
	Name : SCRT_EncryptFinal
	Description: padding 붙이고, padding Block 암호화.
	Parameters
	[in] ctx : 	암호화에 사용될 키를 저장한 컨텍스트 구조체
	[out] out : 암호화된 값
	[out] outl : 암호화된 데이터 길이
	Return Value : 
	Note
*/
/* padding 붙이고, padding Block 암호화. */
SRESULT SCRT_EncryptFinal(SCRT_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
	SRESULT E_SR;
	int i,n,b,bl;

	E_SR = S_FAILED | SL_BLOCK | SF_SCRT_ENCRYPT_FINAL;
	b=ctx->cipher->block_size;

	if (b == 1) /* 패딩이 없는 경우. cfb, ofb 모드가 여기에 해당 */
	{
		*outl=0;
		return S_SUCCESS;
	}

	bl=ctx->buf_len;

	n=b-bl;
	
	/* 패딩 붙인다. */
	for (i=bl; i<b; i++)
		ctx->buf[i]=n;

	ctx->cipher->do_cipher(ctx,out,ctx->buf,b);
	*outl=b;
	return S_SUCCESS;
}

/*	
	Name : SCRT_DecryptUpdate
	Description: padding 제외한 부분  복호화.
	Parameters
	[in] ctx : 복호화 키 컨텍스트 구조체
	[in] out : 복호화된 값
	[in] outl : 복호화된 데이터 길이
	[in] in : 복호화할 데이터
	[in] inl : 복호화할 데이터 길이
	Return Value : 
	Note
*/
/* padding 제외한 부분  복호화.*/
SRESULT SCRT_DecryptUpdate(SCRT_CIPHER_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int inl)
{
	SRESULT E_SR=0;
	int b=0,bl=0,n=0;
	int keep_last=0;

	E_SR = S_FAILED | SL_BLOCK | SF_SCRT_DECRYPT_UPDATE;
	*outl=0;

	if (inl == 0) return E_SR | SR_INPUT_LENGTH_INVALIED ;
	
	b=ctx->cipher->block_size;

	if (b > 1)
	{
		bl=ctx->buf_len;
		n=inl+bl;
		if (n%b == 0)
		{
			if (inl < b)
			{
				memcpy(&(ctx->buf[bl]),in,inl);
				ctx->buf_len=b;
				*outl=0;
				return E_SR | SR_BLOCK_DECRYPT_BLOCK_SIZE_WRONG ;
			}
			keep_last=1;
			inl-=b; 
		}
	}

	SCRT_EncryptUpdate(ctx,out,outl,in,inl);

	/* 패딩 block 처리*/
	if (keep_last)
	{
		memcpy(&(ctx->buf[0]),&(in[inl]),b);
		ctx->buf_len=b;
	}
	return S_SUCCESS;
}

/*	
	Name : SCRT_DecryptFinal
	Description: padding Block 복호화, padding bits 제거.
	Parameters
	[in] ctx : 	복호화키 컨텍스트 구조체
	[in] out : 복호화된 데이터
	[in] outl :  복호화된 데이터 길이
	Return Value : 
	Note
*/
/* padding Block 복호화, padding bits 제거.*/
SRESULT SCRT_DecryptFinal(SCRT_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
	SRESULT E_SR=0;
	int i=0,b=0,n=0;

	E_SR = S_FAILED | SL_BLOCK | SF_SCRT_DECRYPT_FINAL ;

	*outl=0;
	b=ctx->cipher->block_size;
	
	if (b > 1)
	{
		if (ctx->buf_len != b)
			return E_SR | SR_BLOCK_PADDING_BUFFER_LENGTH_WRONG;

		SCRT_EncryptUpdate(ctx,ctx->buf,&n,ctx->buf,0);
	 
		if (n != b)
			return E_SR | SR_BLOCK_PADDING_BLOCK_SIZE_WRONG;
	
		n=ctx->buf[b-1];
		if (n > b)
			return E_SR | SR_BLOCK_PADDING_BIT_NUMBERS_WRONG;
			
		for (i=0; i<n; i++)
		{
			if (ctx->buf[--b] != n)
				return E_SR | SR_BLOCK_PADDING_BIT_VALUE_WRONG;
		}
		n=ctx->cipher->block_size-n;
		for (i=0; i<n; i++)
			out[i]=ctx->buf[i];
		*outl=n;
	}
	else
		*outl=0;

	return S_SUCCESS;
}

/*	
	Name : SCRT_Block_Encrypt
	Description: 암호화에 사용될 키를 설정후 padding 붙힌 Block 암호화
	Parameters
	[in] ctx : 	암호화키 컨텍스트 구조체
	[in] in : 암호화할 평문데이터
	[in] inl : 암호화할 평문데이터 길이
	[in] keydata :  키 구조체
	[in] iv : 초기 벡터값
	[in] out : 암호화된 데이터 
	[in] outl : 암호화된 데이터 길이
	Return Value : 
	Note
*/
/* encrypt init, update, final을 하나로 묶은 함수.*/
SRESULT SCRT_Block_Encrypt(SCRT_CIPHER_CTX *ctx, U8 *in, int inl,U8 *keydata, U8 *iv, U8 *out, int *outl)
{
	SRESULT E_SR;
	long obytes;
	U8 *out1 = NULL, *out2 = NULL; 
	int outl1, outl2;
	int BLOCKSIZE;
	int status;

	E_SR = S_FAILED | SL_BLOCK | SF_SCRT_BLOCK_ENCRYPT ;

	BLOCKSIZE = ctx->cipher->block_size;	

	if (BLOCKSIZE == 1) obytes = inl;
	else
		obytes = ((inl + BLOCKSIZE) / BLOCKSIZE) * BLOCKSIZE ;

    out1 = (U8 *)malloc(obytes);
	out2 = (U8 *)malloc(BLOCKSIZE);

    if(out1 == NULL) 
    {
    	if (out2 != NULL) free(out2); 
    	return E_SR | SR_MEM_ALLOC_FAIL;
    }
	if(out2 == NULL) 
	{
		if (out1 != NULL) free(out1);
		return E_SR | SR_MEM_ALLOC_FAIL;
	}
	
	memset(out1,0,obytes);
	memset(out2,0, BLOCKSIZE);

	outl1= outl2=0;

	status = SCRT_EncryptInit(ctx, ctx->cipher, (U8 *)keydata, (U8 *)iv);		 
	if(ERROR_FAILED(status))
	{	
		FREE(out1);
		FREE(out2);
		return E_SR | SR_BLOCK_ENCRYPT_INIT_FAILED;
	}

	status = SCRT_EncryptUpdate(ctx, out1, &outl1, in, inl);				 
	if(ERROR_FAILED(status))
	{	
		FREE(out1);
		FREE(out2);
		return status;
	}

	status = SCRT_EncryptFinal(ctx, out2, &outl2);					 
	if(ERROR_FAILED(status))
	{	
		FREE(out1);
		FREE(out2);
		return E_SR | SR_BLOCK_ENCRYPT_FINAL_FAILED;
	}

	memcpy(out1+outl1,out2,outl2);
	outl1 = outl1 + outl2;
	memcpy(out,out1,outl1);
	*outl = outl1;

	FREE(out1);
	FREE(out2);
	
	return S_SUCCESS;
}

/*	
	Name : SCRT_Block_Decrypt
	Description: 복호화에 사용될 키를 설정후 padding 붙힌 Block 복호화
	Parameters
	[in] ctx : 	암호화키 컨텍스트 구조체
	[in] in : 복호화할 암호화 데이터
	[in] inl : 복호화할 암호화 데이터 길이
	[in] keydata :  키 구조체
	[in] iv : 초기 벡터값
	[in] out : 복호화된 데이터 
	[in] outl : 복호화된 데이터 길이
	Return Value : 
	Note
*/
/* Decryption init, update, final을 하나로 묶은 함수 */
SRESULT SCRT_Block_Decrypt(SCRT_CIPHER_CTX *ctx, U8 *in, int inl,  U8 *keydata, U8 *iv,U8 *out, int *outl)
{
	/* not using crypto board */
	SRESULT E_SR;
	long obytes;
	U8 *out1 = NULL, *out2 = NULL; 
	int outl1, outl2;
	int BLOCKSIZE;
	int status;
	
	E_SR = S_FAILED | SL_BLOCK | SF_SCRT_BLOCK_DECRYPT;
	
	BLOCKSIZE = ctx->cipher->block_size;	
	
	if (BLOCKSIZE == 1) obytes = inl;
	else
		obytes = ((inl + BLOCKSIZE) / BLOCKSIZE) * BLOCKSIZE ;

    out1 = (U8 *)malloc(obytes);
	out2 = (U8 *)malloc(BLOCKSIZE);

	if(out1 == NULL) 
    {
    	if (out2 != NULL) free(out2); 
    	return E_SR | SR_MEM_ALLOC_FAIL;
    }
	if(out2 == NULL) 
	{
		if (out1 != NULL) free(out1); 
		return E_SR | SR_MEM_ALLOC_FAIL;
	}
	
    memset(out1,0,obytes);
	memset(out2,0, BLOCKSIZE);

	outl1= outl2=0;

	status = SCRT_DecryptInit(ctx, ctx->cipher, (U8 *)keydata, (U8 *)iv);		
	if(ERROR_FAILED(status)) 
	{	
		FREE(out1);
		FREE(out2);
		return E_SR | SR_BLOCK_DECRYPT_INIT_FAILED;
	}

	status = SCRT_DecryptUpdate(ctx, out1, &outl1, in, inl);			
	if(ERROR_FAILED(status)) 
	{	
		FREE(out1);
		FREE(out2);
		return E_SR | SR_BLOCK_DECRYPT_UPDATE_FAILED;
	}

	status = SCRT_DecryptFinal(ctx, out2, &outl2);
	if(ERROR_FAILED(status)) 
	{	
		FREE(out1);
		FREE(out2);
		return E_SR | SR_BLOCK_DECRYPT_FINAL_FAILED;
	}

	memcpy(out1+outl1,out2,outl2);
	outl1 = outl1 + outl2;
	memcpy(out,out1,outl1);
	*outl = outl1;
	
		
	FREE(out1);
	FREE(out2);
	
	return S_SUCCESS;
}
