#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../include/scrt.h"
#include "../include/scrt_object.h"
#include "../include/tnkmscrypto.h"
#ifdef _DEBUG
#include <vld.h>
#endif
extern TN_ULONG  m_tcl_err_code=TNR_SUCCESS;

/* BLOCK */
#ifdef WIN32
TCL_API TN_RV TCL_Block_Encrypt(TN_LONG alg_nid, TN_USTRING_PTR in, TN_USTRING_PTR key, TN_USTRING_PTR iv, TN_USTRING_PTR out)
#else
TN_RV TCL_Block_Encrypt(TN_LONG alg_nid, TN_USTRING_PTR in, TN_USTRING_PTR key, TN_USTRING_PTR iv, TN_USTRING_PTR out)
#endif
{
	TN_RV ret=-1;
	long outbytes=0;
	int BLOCKSIZE=0;
	SCRT_CIPHER_CTX sctx;
	TN_USTRING usOut;
	TN_RV err_code = TN_FAILED | TNL_BLOCK | TNF_BLOCK_ENCRYPT ;

	memset(&usOut, 0x00, sizeof(TN_USTRING));

	if( (in == NULL) || (key == NULL) || (iv == NULL) || (out == NULL) )
	{
		ret = m_tcl_err_code = (err_code | TNR_ARGUMENTS_BAD);
		goto err ;
	}

	/* 선택한 알고리즘을 파악한다. */
	switch(alg_nid)
	{
		/* SEED */
 		case NID_seed_cbc :		sctx.cipher = SCRT_seed_cbc(); break;
		case NID_seed_ecb :		sctx.cipher = SCRT_seed_ecb(); break;
		case NID_seed_cfb64 :	sctx.cipher = SCRT_seed_cfb(); break;
		case NID_seed_ofb64 :	sctx.cipher = SCRT_seed_ofb(); break;
		case NID_seed_cfb128:	sctx.cipher = SCRT_seed_cfb128(); break;
		case NID_seed_ctr128:	sctx.cipher = SCRT_seed_ctr(); break;

		/* SEED-256 */
 		case TN_BLOCK_SEED_256_ECB :	sctx.cipher = SCRT_seed256_ecb(); break;
		case TN_BLOCK_SEED_256_CBC :	sctx.cipher = SCRT_seed256_cbc(); break;
		case TN_BLOCK_SEED_256_CFB_64 :	sctx.cipher = SCRT_seed256_cfb(); break;
		case TN_BLOCK_SEED_256_OFB :	sctx.cipher = SCRT_seed256_ofb(); break;
		case TN_BLOCK_SEED_256_CTR:		sctx.cipher = SCRT_seed256_ctr(); break;

		/* AES */ 
		case NID_aes_128_ecb	 :	sctx.cipher = SCRT_aes_128_ecb(); break;	 
		case NID_aes_192_ecb	 :	sctx.cipher = SCRT_aes_192_ecb(); break;	 
		case NID_aes_256_ecb	 :	sctx.cipher = SCRT_aes_256_ecb(); break;	 
		case NID_aes_128_cbc	 :	sctx.cipher = SCRT_aes_128_cbc(); break;	 
		case NID_aes_192_cbc	 :	sctx.cipher = SCRT_aes_192_cbc(); break;	 
		case NID_aes_256_cbc	 :	sctx.cipher = SCRT_aes_256_cbc(); break;	 
		case NID_aes_128_cfb128	 :	sctx.cipher = SCRT_aes_128_cfb(); break;
		case NID_aes_192_cfb128	 :	sctx.cipher = SCRT_aes_192_cfb(); break;
		case NID_aes_256_cfb128	 :	sctx.cipher = SCRT_aes_256_cfb(); break;
		case NID_aes_128_ofb128	 :	sctx.cipher = SCRT_aes_128_ofb(); break;
		case NID_aes_192_ofb128	 :	sctx.cipher = SCRT_aes_192_ofb(); break;
		case NID_aes_256_ofb128	 :	sctx.cipher = SCRT_aes_256_ofb(); break;
		case NID_aes_128_ctr128	 :	sctx.cipher = SCRT_aes_128_ctr(); break;
		case NID_aes_192_ctr128	 :	sctx.cipher = SCRT_aes_192_ctr(); break;
		case NID_aes_256_ctr128	 :	sctx.cipher = SCRT_aes_256_ctr(); break;

		case NID_aria_128_ecb	 :	sctx.cipher = SCRT_aria_128_ecb(); break;
		case NID_aria_192_ecb	 :	sctx.cipher = SCRT_aria_192_ecb(); break;
		case NID_aria_256_ecb	 :	sctx.cipher = SCRT_aria_256_ecb(); break;
		case NID_aria_128_cbc	 :	sctx.cipher = SCRT_aria_128_cbc(); break;	
		case NID_aria_192_cbc	 :	sctx.cipher = SCRT_aria_192_cbc(); break;
		case NID_aria_256_cbc	 :	sctx.cipher = SCRT_aria_256_cbc(); break;
		case NID_aria_128_cfb128 :	sctx.cipher = SCRT_aria_128_cfb128(); break;
		case NID_aria_192_cfb128 :	sctx.cipher = SCRT_aria_192_cfb128(); break;
		case NID_aria_256_cfb128 :	sctx.cipher = SCRT_aria_256_cfb128(); break;
		case NID_aria_128_ofb128 :	sctx.cipher = SCRT_aria_128_ofb128(); break;
		case NID_aria_192_ofb128 :	sctx.cipher = SCRT_aria_192_ofb128(); break;
		case NID_aria_256_ofb128 :	sctx.cipher = SCRT_aria_256_ofb128(); break;
		case NID_aria_128_ctr128 :	sctx.cipher = SCRT_aria_128_ctr128(); break;
		case NID_aria_192_ctr128 :	sctx.cipher = SCRT_aria_192_ctr128(); break;
		case NID_aria_256_ctr128 :	sctx.cipher = SCRT_aria_256_ctr128(); break;

		/* LEA */ 
		case NID_lea_128_ecb	 :	sctx.cipher = SCRT_lea_128_ecb(); break;
		case NID_lea_192_ecb	 :	sctx.cipher = SCRT_lea_192_ecb(); break;
		case NID_lea_256_ecb	 :	sctx.cipher = SCRT_lea_256_ecb(); break;
		case NID_lea_128_cbc	 :	sctx.cipher = SCRT_lea_128_cbc(); break;	
		case NID_lea_192_cbc	 :	sctx.cipher = SCRT_lea_192_cbc(); break;
		case NID_lea_256_cbc	 :	sctx.cipher = SCRT_lea_256_cbc(); break;
		case NID_lea_128_cfb128 :	sctx.cipher = SCRT_lea_128_cfb128(); break;
		case NID_lea_192_cfb128 :	sctx.cipher = SCRT_lea_192_cfb128(); break;
		case NID_lea_256_cfb128 :	sctx.cipher = SCRT_lea_256_cfb128(); break;
		case NID_lea_128_ofb128 :	sctx.cipher = SCRT_lea_128_ofb128(); break;
		case NID_lea_192_ofb128 :	sctx.cipher = SCRT_lea_192_ofb128(); break;
		case NID_lea_256_ofb128 :	sctx.cipher = SCRT_lea_256_ofb128(); break;
		case NID_lea_128_ctr128 :	sctx.cipher = SCRT_lea_128_ctr128(); break;
		case NID_lea_192_ctr128 :	sctx.cipher = SCRT_lea_192_ctr128(); break;
		case NID_lea_256_ctr128 :	sctx.cipher = SCRT_lea_256_ctr128(); break;

		default:
			ret = m_tcl_err_code = (err_code | TNR_BLOCK_ALGO_NID_NOT_SUPPORTED);
			goto err;
			break;
	}
	
	BLOCKSIZE = sctx.cipher->block_size ;

	/* 패딩을 붙였을 경우 ciphertext길이 계산 */
	if (BLOCKSIZE == 1) outbytes = in->length;
	else
		outbytes = ((in->length + BLOCKSIZE) / BLOCKSIZE) * BLOCKSIZE ;

	if(out->value == NULL) 
	{
		out->length = outbytes;
		return TNR_OK;
	}

	/* 패딩을 붙였을 때의 길이만큼 메모리를 할당해준다. */
	usOut.value = (U8 *)calloc(1, outbytes );

	ret = SCRT_Block_Encrypt(&sctx, in->value, in->length , key->value, iv->value, usOut.value , &(usOut.length));
	if(ret)
	{
		switch(ret & 0x00000fff)
		{
		case SR_MEM_ALLOC_FAIL:
			ret = m_tcl_err_code = (err_code | TNR_MEM_ALLOC_FAILED);
			break;
		case SR_BLOCK_ENCRYPT_INIT_FAILED:
			ret = m_tcl_err_code = (err_code | TNR_BLOCK_ENCRYPT_INIT_FAILED);
			break;
		case SR_BLOCK_ENCRYPT_FINAL_FAILED:
			ret = m_tcl_err_code = (err_code | TNR_BLOCK_ENCRYPT_FINAL_FAILED);
			break;
		case SR_BLOCK_PADDING_BLOCK_SIZE_WRONG:
			ret = m_tcl_err_code = (err_code | TNR_BLOCK_PADDING_BLOCK_SIZE_WRONG);
			break;
		}
		goto err;
	}

	if( out->length < usOut.length)
	{
		ret = m_tcl_err_code = (err_code | TNR_BUFFER_TOO_SMALL_FAILED);
		goto err;		
	}
	
	memcpy(out->value, usOut.value, usOut.length);
	out->length = usOut.length;

	ret = TNR_OK;
err:
	if(usOut.value!=NULL) FREE(usOut.value);

	return ret;
}

#ifdef WIN32
TCL_API TN_RV TCL_Block_Decrypt(TN_LONG alg_nid, TN_USTRING_PTR in, TN_USTRING_PTR key, TN_USTRING_PTR iv, TN_USTRING_PTR out)
#else
TN_RV TCL_Block_Decrypt(TN_LONG alg_nid, TN_USTRING_PTR in, TN_USTRING_PTR key, TN_USTRING_PTR iv, TN_USTRING_PTR out)
#endif
{
	TN_RV ret=-1;
	long outbytes=0;
	int BLOCKSIZE=0;
	SCRT_CIPHER_CTX sctx;
	TN_USTRING usOut;
	TN_RV err_code = TN_FAILED | TNL_BLOCK | TNF_BLOCK_DECRYPT ;

	memset(&usOut, 0x00, sizeof(TN_USTRING));

	if( (in == NULL) || (key == NULL) || (iv == NULL) || (out == NULL) )
	{
		ret = m_tcl_err_code = (err_code | TNR_ARGUMENTS_BAD);
		goto err ;
	}

	/* 선택한 알고리즘을 파악한다. */
	switch(alg_nid)
	{
		/* SEED */
 		case NID_seed_cbc :		sctx.cipher = SCRT_seed_cbc(); break;
		case NID_seed_ecb :		sctx.cipher = SCRT_seed_ecb(); break;
		case NID_seed_cfb64 :	sctx.cipher = SCRT_seed_cfb(); break;
		case NID_seed_ofb64 :	sctx.cipher = SCRT_seed_ofb(); break;
		case NID_seed_cfb128:	sctx.cipher = SCRT_seed_cfb128(); break;
		case NID_seed_ctr128:	sctx.cipher = SCRT_seed_ctr(); break;

		/* SEED-256 */
 		case TN_BLOCK_SEED_256_ECB :	sctx.cipher = SCRT_seed256_ecb(); break;
		case TN_BLOCK_SEED_256_CBC :	sctx.cipher = SCRT_seed256_cbc(); break;
		case TN_BLOCK_SEED_256_CFB_64 :	sctx.cipher = SCRT_seed256_cfb(); break;
		case TN_BLOCK_SEED_256_OFB :	sctx.cipher = SCRT_seed256_ofb(); break;
		case TN_BLOCK_SEED_256_CTR:		sctx.cipher = SCRT_seed256_ctr(); break;

		/* AES */ 
		case NID_aes_128_ecb	 :	sctx.cipher = SCRT_aes_128_ecb(); break;	 
		case NID_aes_192_ecb	 :	sctx.cipher = SCRT_aes_192_ecb(); break;	 
		case NID_aes_256_ecb	 :	sctx.cipher = SCRT_aes_256_ecb(); break;	 
		case NID_aes_128_cbc	 :	sctx.cipher = SCRT_aes_128_cbc(); break;	 
		case NID_aes_192_cbc	 :	sctx.cipher = SCRT_aes_192_cbc(); break;	 
		case NID_aes_256_cbc	 :	sctx.cipher = SCRT_aes_256_cbc(); break;	 
		case NID_aes_128_cfb128	 :	sctx.cipher = SCRT_aes_128_cfb(); break;
		case NID_aes_192_cfb128	 :	sctx.cipher = SCRT_aes_192_cfb(); break;
		case NID_aes_256_cfb128	 :	sctx.cipher = SCRT_aes_256_cfb(); break;
		case NID_aes_128_ofb128	 :	sctx.cipher = SCRT_aes_128_ofb(); break;
		case NID_aes_192_ofb128	 :	sctx.cipher = SCRT_aes_192_ofb(); break;
		case NID_aes_256_ofb128	 :	sctx.cipher = SCRT_aes_256_ofb(); break;
		case NID_aes_128_ctr128	 :	sctx.cipher = SCRT_aes_128_ctr(); break;
		case NID_aes_192_ctr128	 :	sctx.cipher = SCRT_aes_192_ctr(); break;
		case NID_aes_256_ctr128	 :	sctx.cipher = SCRT_aes_256_ctr(); break;

		case NID_aria_128_ecb	 :	sctx.cipher = SCRT_aria_128_ecb(); break;
		case NID_aria_192_ecb	 :	sctx.cipher = SCRT_aria_192_ecb(); break;
		case NID_aria_256_ecb	 :	sctx.cipher = SCRT_aria_256_ecb(); break;
		case NID_aria_128_cbc	 :	sctx.cipher = SCRT_aria_128_cbc(); break;	
		case NID_aria_192_cbc	 :	sctx.cipher = SCRT_aria_192_cbc(); break;
		case NID_aria_256_cbc	 :	sctx.cipher = SCRT_aria_256_cbc(); break;
		case NID_aria_128_cfb128 :	sctx.cipher = SCRT_aria_128_cfb128(); break;
		case NID_aria_192_cfb128 :	sctx.cipher = SCRT_aria_192_cfb128(); break;
		case NID_aria_256_cfb128 :	sctx.cipher = SCRT_aria_256_cfb128(); break;
		case NID_aria_128_ofb128 :	sctx.cipher = SCRT_aria_128_ofb128(); break;
		case NID_aria_192_ofb128 :	sctx.cipher = SCRT_aria_192_ofb128(); break;
		case NID_aria_256_ofb128 :	sctx.cipher = SCRT_aria_256_ofb128(); break;
		case NID_aria_128_ctr128 :	sctx.cipher = SCRT_aria_128_ctr128(); break;
		case NID_aria_192_ctr128 :	sctx.cipher = SCRT_aria_192_ctr128(); break;
		case NID_aria_256_ctr128 :	sctx.cipher = SCRT_aria_256_ctr128(); break;

		/* LEA */ 
		case NID_lea_128_ecb	 :	sctx.cipher = SCRT_lea_128_ecb(); break;
		case NID_lea_192_ecb	 :	sctx.cipher = SCRT_lea_192_ecb(); break;
		case NID_lea_256_ecb	 :	sctx.cipher = SCRT_lea_256_ecb(); break;
		case NID_lea_128_cbc	 :	sctx.cipher = SCRT_lea_128_cbc(); break;	
		case NID_lea_192_cbc	 :	sctx.cipher = SCRT_lea_192_cbc(); break;
		case NID_lea_256_cbc	 :	sctx.cipher = SCRT_lea_256_cbc(); break;
		case NID_lea_128_cfb128 :	sctx.cipher = SCRT_lea_128_cfb128(); break;
		case NID_lea_192_cfb128 :	sctx.cipher = SCRT_lea_192_cfb128(); break;
		case NID_lea_256_cfb128 :	sctx.cipher = SCRT_lea_256_cfb128(); break;
		case NID_lea_128_ofb128 :	sctx.cipher = SCRT_lea_128_ofb128(); break;
		case NID_lea_192_ofb128 :	sctx.cipher = SCRT_lea_192_ofb128(); break;
		case NID_lea_256_ofb128 :	sctx.cipher = SCRT_lea_256_ofb128(); break;
		case NID_lea_128_ctr128 :	sctx.cipher = SCRT_lea_128_ctr128(); break;
		case NID_lea_192_ctr128 :	sctx.cipher = SCRT_lea_192_ctr128(); break;
		case NID_lea_256_ctr128 :	sctx.cipher = SCRT_lea_256_ctr128(); break;

		default:
			ret = m_tcl_err_code = (err_code | TNR_BLOCK_ALGO_NID_NOT_SUPPORTED);
			goto err;
			break;
	}
	
	BLOCKSIZE = sctx.cipher->block_size ;

	/* 패딩을 붙였을 경우 ciphertext길이 계산 */
	if (BLOCKSIZE == 1) outbytes = in->length;
	else
		outbytes = ((in->length + BLOCKSIZE) / BLOCKSIZE) * BLOCKSIZE ;

	if(out->value == NULL) 
	{
		out->length = outbytes;
		return TNR_OK;
	}

	/* 패딩을 붙였을 때의 길이만큼 메모리를 할당해준다. */
	usOut.value = (U8 *)calloc(1, outbytes );

	ret = SCRT_Block_Decrypt(&sctx, in->value, in->length, key->value, iv->value, usOut.value , &(usOut.length));
	if(ret)
	{
		switch(ret & 0x00000fff)
		{
		case SR_MEM_ALLOC_FAIL:
			ret = m_tcl_err_code = (err_code | TNR_MEM_ALLOC_FAILED);
			break;
		case SR_BLOCK_CIPHER_EMPTY_FAILED:
			ret = m_tcl_err_code = (err_code | TNR_BLOCK_CIPHER_EMPTY_FAILED);
			break;
		case SR_BLOCK_PADDING_BUFFER_LENGTH_WRONG:
			ret = m_tcl_err_code = (err_code | TNR_BLOCK_PADDING_BUFFER_LENGTH_WRONG);
			break;
		case SR_BLOCK_PADDING_BLOCK_SIZE_WRONG:
			ret = m_tcl_err_code = (err_code | TNR_BLOCK_PADDING_BLOCK_SIZE_WRONG);
			break;
		case SR_BLOCK_DECRYPT_BLOCK_SIZE_WRONG:
			ret = m_tcl_err_code = (err_code | TNR_BLOCK_DECRYPT_BLOCK_SIZE_WRONG);
			break;
		case SR_BLOCK_PADDING_BIT_NUMBERS_WRONG:
			ret = m_tcl_err_code = (err_code | TNR_BLOCK_PADDING_BIT_NUMBERS_WRONG);
			break;
		case SR_BLOCK_PADDING_BIT_VALUE_WRONG:
			ret = m_tcl_err_code = (err_code | TNR_BLOCK_PADDING_BIT_VALUE_WRONG);
			break;
		}

		goto err;
	}

	if( out->length < usOut.length)
	{
		ret = m_tcl_err_code = (err_code | TNR_BUFFER_TOO_SMALL_FAILED);
		goto err;		
	}
	
	memcpy(out->value, usOut.value, usOut.length);
	out->length = usOut.length;

	ret = TNR_OK;
err:
	if(usOut.value!=NULL) FREE(usOut.value);

	return ret;
}


/* HASH */
#ifdef WIN32
TCL_API TN_RV TCL_Digest(TN_LONG alg_nid, TN_USTRING_PTR in, TN_USTRING_PTR out)
#else
TN_RV TCL_Digest(TN_LONG alg_nid, TN_USTRING_PTR in, TN_USTRING_PTR out)
#endif
{
	TN_RV ret=-1;
	TN_LONG dLen=0;
	TN_USTRING usOut;
	SCRT_MD_CTX sctx;
	TN_RV err_code = TN_FAILED | TNL_HASH | TNF_DIGEST ;

	memset(&usOut, 0x00, sizeof(TN_USTRING));

	if( (in == NULL)  || (out == NULL) )
	{
		ret = m_tcl_err_code = (err_code | TNR_ARGUMENTS_BAD);
		goto err ;
	}

	switch(alg_nid)
	{
		case NID_sha256:
			sctx.digest = SCRT_sha256();
			break;
		case NID_sha512:
			sctx.digest = SCRT_sha512();
			break;
		case NID_lsh256:
			sctx.digest = SCRT_lsh256();
			break;
		case NID_lsh512:
			sctx.digest = SCRT_lsh512();
			break;
		default :
			ret = m_tcl_err_code = (err_code | TNR_DIGEST_TYPE_NOT_SUPPORTED);
			goto err;
	}

	dLen = sctx.digest->md_size;

	if( out->value == NULL )
	{
		out->length = dLen;
		return TNR_OK;
	}

	usOut.value = (U8*)calloc(dLen, sizeof(U8));
	if(!usOut.value)
	{
		ret = m_tcl_err_code = (err_code | TNR_MEM_ALLOC_FAILED);
		goto err;			
	}	

	usOut.length = dLen;
	ret = SCRT_Digest(&sctx, in->value, in->length, usOut.value, (unsigned int *)&(usOut.length));
	if(ERROR_FAILED(ret))
	{	
		ret = m_tcl_err_code = (err_code | TNR_DIGEST_FINAL_FAILED);
		goto err;
	}

	if(out->length < usOut.length)
	{
		ret = m_tcl_err_code = (err_code | TNR_BUFFER_TOO_SMALL_FAILED);
		goto err;		
	}

	memcpy(out->value, usOut.value, usOut.length);

	ret =TNR_OK;
err:
	if(usOut.value!=NULL) free(usOut.value);
	return ret;
}

/* HMAC */
#ifdef WIN32
TCL_API TN_RV TCL_HMAC(TN_LONG alg_nid, TN_USTRING_PTR key, TN_USTRING_PTR in, TN_USTRING_PTR out)
#else
TN_RV TCL_HMAC(TN_LONG alg_nid, TN_USTRING_PTR key, TN_USTRING_PTR in, TN_USTRING_PTR out)
#endif
{
	TN_RV ret=-1;
	TN_RV err_code = TN_FAILED | TNL_MAC | TNF_HMAC ;
	TN_USTRING usOut;
	SCRT_MD sctx;

	memset(&usOut, 0x00, sizeof(TN_USTRING));

	if( (key == NULL) || (in == NULL) || (out == NULL) )
	{
		ret = m_tcl_err_code = (err_code | TNR_ARGUMENTS_BAD);
		goto err ;
	}

	memset(&sctx,0x00,sizeof(SCRT_MD));

	switch(alg_nid)
	{
		case NID_sha256		:	
			sctx = *SCRT_sha256(); 
			break;
		case NID_sha512		:	
			sctx = *SCRT_sha512(); 
			break;
		default : 
			ret = m_tcl_err_code = (err_code | TNR_DIGEST_TYPE_NOT_SUPPORTED);
			goto err;
			break;
	}

	if(out->value == NULL)
	{
		if(out->length <= 0)
			out->length = sctx.md_size;	
		return TNR_OK;
	}

	usOut.length = out->length;
	usOut.value = (U8*)calloc(usOut.length, sizeof(U8));
	if(!usOut.value)
	{
		ret = m_tcl_err_code = (err_code | TNR_MEM_ALLOC_FAILED);
		goto err;			
	}

	ret = SCRT_HMAC2(&sctx, key->value, key->length, in->value, in->length, usOut.value, usOut.length);
	if(ERROR_FAILED(ret))
	{	
		ret = m_tcl_err_code = (err_code | TNR_MAC_HASH_FAILED);
		goto err;
	}

	if(out->length < usOut.length)
	{
		ret = m_tcl_err_code = (err_code | TNR_BUFFER_TOO_SMALL_FAILED);
		goto err;		
	}	

	memcpy(out->value, usOut.value, usOut.length);
	
	ret=TNR_OK;
err:
	if(usOut.value!=0) free(usOut.value);
	memset(&usOut, 0x00, sizeof(TN_USTRING));

	return ret;
}

/* RANDOM */
#ifdef WIN32
TCL_API TN_RV TCL_GenerateRandom(TN_LONG bytes, TN_USTRING_PTR out)
#else
TN_RV TCL_GenerateRandom(TN_LONG bytes, TN_USTRING_PTR out)
#endif
{
	TN_RV ret=-1;
	int mode = NID_sha256;
	TN_RV err_code = TN_FAILED | TNL_RANDOM | TNF_GEN_RANDOM ;
	TN_BYTE *tmpout = NULL;

	if( bytes <= 0 )
	{
		ret = m_tcl_err_code = (err_code | TNR_ARGUMENTS_BAD);
		goto err ;
	}

	if(out->value == NULL)
	{
		out->length = bytes;	
		return TNR_OK;
	}
		
	switch(mode) {
	case NID_sha256:
		tmpout = (TN_BYTE *)calloc(bytes, sizeof(TN_BYTE));
		if(!tmpout)
		{
			ret = m_tcl_err_code = (err_code | TNR_MEM_ALLOC_FAILED);
			goto err;			
		}
		ret = SCRT_GenerateRandom(bytes, mode, tmpout);
		if(ret!=TNR_OK) {
			ret = m_tcl_err_code = (err_code | TNR_RANDOM_ALGO_NOT_SUPPORTED);
			goto err;
		}
		break;
	default:
		ret = m_tcl_err_code = (err_code | TNR_RANDOM_ALGO_NOT_SUPPORTED);
		goto err;
		break;
	}

	if(out->length < (TN_ULONG)bytes)
	{
		ret = m_tcl_err_code = (err_code | TNR_BUFFER_TOO_SMALL_FAILED);
		goto err;		
	}
	
	memcpy(out->value, tmpout, bytes);
	out->length = bytes;

	ret = TNR_OK;
	
err:
	if(tmpout!=NULL) { 
		memset(tmpout,0,bytes); free(tmpout); 
	}

	return ret;
}

/* ERROR */
#ifdef WIN32
TCL_API TN_LONG TCL_GetErrorCode(void)
#else
TN_LONG TCL_GetErrorCode(void)
#endif
{
	return (m_tcl_err_code & 0x00000FFF);
}
