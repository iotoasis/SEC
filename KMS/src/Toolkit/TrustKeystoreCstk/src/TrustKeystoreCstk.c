/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     TrustKeystoreCstk.c

	 Creadted by DEV3

************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef LIGHTWEIGHT_TKS_CSTK

#ifdef WIN32
#include "../../tnkmscryptolite/tnkmscryptolite/include/tnkmscryptolite.h"
#else
	#include "tnkmscryptolite.h"
#endif
#else
#ifdef WIN32
	#include "../../tnkmscrypto/tnkmscrypto/include/tnkmscrypto.h"
#else
	#include "tnkmscrypto.h"
#endif
#endif

#ifdef WIN32
#include "../../TrustKeystoreAgent/TrustKeystoreAgent/TrustKeystoreAgent.h"
#else
#include "TrustKeystoreAgent.h"
#endif
#include "TrustKeystoreCstk.h"

#ifdef WIN32
#ifdef LIGHTWEIGHT_TKS_CSTK
#pragma comment(lib, "tnkmscryptolite.lib")
#ifdef DEVICE_MODE_TKS_CSTK
#pragma comment(lib, "TKSAgentLite.lib")
#else
#pragma comment(lib, "TKSAgent.lib")
#endif
#else
#pragma comment(lib, "tnkmscrypto.lib")
#ifdef DEVICE_MODE_TKS_CSTK
#pragma comment(lib, "TKSAgentLite.lib")
#else
#pragma comment(lib, "TKSAgentAdv.lib")
#endif
#endif
#endif

#define TKS_CSTK_KEK_LEN		32
#define TKS_CSTK_KEK_KEY_LEN	16
#define TKS_CSTK_KEK_IV_LEN		16

extern int  m_tkscstk_err_code=TK_CSTK_SUCCESS;

/* Internal Function */
int GetCipherIDByChar(char *algo)
{
	if( strcmp(algo,"SHA256") == 0 || strcmp(algo, "sha256") == 0 || strcmp(algo,"HMAC-SHA256") == 0 || strcmp(algo, "hmac-sha256") == 0)
	{
		return TN_DIGEST_SHA256;
	}
	else if( strcmp(algo,"SHA512") == 0 || strcmp(algo ,"sha512" ) == 0 || strcmp(algo,"HMAC-SHA512") == 0 || strcmp(algo, "hmac-sha512") == 0)
	{
		return TN_DIGEST_SHA512;
	}
	else if( strcmp(algo,"LSH256") == 0 || strcmp(algo ,"lsh256" ) == 0 )
	{
		return TN_DIGEST_LSH256;
	}
	else if( strcmp(algo,"LSH512") == 0 || strcmp(algo ,"lsh512" ) == 0 )
	{
		return TN_DIGEST_LSH512;
	}
	else if( strcmp(algo,"SEED-128_CBC") == 0 || strcmp(algo ,"seed-128_cbc" ) == 0 )
	{
		return TN_BLOCK_SEED_CBC;
	}
	else if( strcmp(algo,"SEED-128_OFB") == 0 || strcmp(algo ,"seed-128_ofb" ) == 0 )
	{
		return TN_BLOCK_SEED_OFB;
	}
	else if( strcmp(algo,"SEED-128_CFB") == 0 || strcmp(algo ,"seed-128_cfb" ) == 0 )
	{
		return TN_BLOCK_SEED_CFB;
	}
	else if( strcmp(algo,"SEED-128_ECB") == 0 || strcmp(algo ,"seed-128_ecb" ) == 0 )
	{
		return TN_BLOCK_SEED_ECB;
	}
	else if( strcmp(algo,"SEED-128_CTR") == 0 || strcmp(algo ,"seed-128_ctr" ) == 0 )
	{
		return TN_BLOCK_SEED_CTR;
	}
	else if( strcmp(algo,"ARIA-128_CBC") == 0 || strcmp(algo ,"aria-128_cbc" ) == 0 )
	{
		return TN_BLOCK_ARIA_128_CBC;
	}
	else if( strcmp(algo,"ARIA-128_OFB") == 0 || strcmp(algo ,"aria-128_ofb" ) == 0 )
	{
		return TN_BLOCK_ARIA_128_OFB;
	}
	else if( strcmp(algo,"ARIA-128_CFB") == 0 || strcmp(algo ,"aria-128_cfb" ) == 0 )
	{
		return TN_BLOCK_ARIA_128_CFB;
	}
	else if( strcmp(algo,"ARIA-128_ECB") == 0 || strcmp(algo ,"aria-128_ecb" ) == 0 )
	{
		return TN_BLOCK_ARIA_128_ECB;
	}
	else if( strcmp(algo,"ARIA-128_CTR") == 0 || strcmp(algo ,"aria-128_ctr" ) == 0 )
	{
		return TN_BLOCK_ARIA_128_CTR;
	}
	else if( strcmp(algo,"ARIA-192_CBC") == 0 || strcmp(algo ,"aria-192_cbc" ) == 0 )
	{
		return TN_BLOCK_ARIA_192_CBC;
	}
	else if( strcmp(algo,"ARIA-192_OFB") == 0 || strcmp(algo ,"aria-192_ofb" ) == 0 )
	{
		return TN_BLOCK_ARIA_192_OFB;
	}
	else if( strcmp(algo,"ARIA-192_CFB") == 0 || strcmp(algo ,"aria-192_cfb" ) == 0 )
	{
		return TN_BLOCK_ARIA_192_CFB;
	}
	else if( strcmp(algo,"ARIA-192_ECB") == 0 || strcmp(algo ,"aria-192_ecb" ) == 0 )
	{
		return TN_BLOCK_ARIA_192_ECB;
	}
	else if( strcmp(algo,"ARIA-192_CTR") == 0 || strcmp(algo ,"aria-192_ctr" ) == 0 )
	{
		return TN_BLOCK_ARIA_192_CTR;
	}
	else if( strcmp(algo,"ARIA-256_CBC") == 0 || strcmp(algo ,"aria-256_cbc" ) == 0 )
	{
		return TN_BLOCK_ARIA_256_CBC;
	}
	else if( strcmp(algo,"ARIA-256_OFB") == 0 || strcmp(algo ,"aria-256_ofb" ) == 0 )
	{
		return TN_BLOCK_ARIA_256_OFB;
	}
	else if( strcmp(algo,"ARIA-256_CFB") == 0 || strcmp(algo ,"aria-256_cfb" ) == 0 )
	{
		return TN_BLOCK_ARIA_256_CFB;
	}
	else if( strcmp(algo,"ARIA-256_ECB") == 0 || strcmp(algo ,"aria-256_ecb" ) == 0 )
	{
		return TN_BLOCK_ARIA_256_ECB;
	}
	else if( strcmp(algo,"ARIA-256_CTR") == 0 || strcmp(algo ,"aria-256_ctr" ) == 0 )
	{
		return TN_BLOCK_ARIA_256_CTR;
	}
	else if( strcmp(algo,"AES-128_CBC") == 0 || strcmp(algo ,"aes-128_cbc" ) == 0 )
	{
		return TN_BLOCK_AES_128_CBC;
	}
	else if( strcmp(algo,"AES-128_OFB") == 0 || strcmp(algo ,"aes-128_ofb" ) == 0 )
	{
		return TN_BLOCK_AES_128_OFB;
	}
	else if( strcmp(algo,"AES-128_CFB") == 0 || strcmp(algo ,"aes-128_cfb" ) == 0 )
	{
		return TN_BLOCK_AES_128_CFB;
	}
	else if( strcmp(algo,"AES-128_ECB") == 0 || strcmp(algo ,"aes-128_ecb" ) == 0 )
	{
		return TN_BLOCK_AES_128_ECB;
	}
	else if( strcmp(algo,"AES-128_CTR") == 0 || strcmp(algo ,"aes-128_ctr" ) == 0 )
	{
		return TN_BLOCK_AES_128_CTR;
	}
	else if( strcmp(algo,"AES-192_CBC") == 0 || strcmp(algo ,"aes-192_cbc" ) == 0 )
	{
		return TN_BLOCK_AES_192_CBC;
	}
	else if( strcmp(algo,"AES-192_OFB") == 0 || strcmp(algo ,"aes-192_ofb" ) == 0 )
	{
		return TN_BLOCK_AES_192_OFB;
	}
	else if( strcmp(algo,"AES-192_CFB") == 0 || strcmp(algo ,"aes-192_cfb" ) == 0 )
	{
		return TN_BLOCK_AES_192_CFB;
	}
	else if( strcmp(algo,"AES-192_ECB") == 0 || strcmp(algo ,"aes-192_ecb" ) == 0 )
	{
		return TN_BLOCK_AES_192_ECB;
	}
	else if( strcmp(algo,"AES-192_CTR") == 0 || strcmp(algo ,"aes-192_ctr" ) == 0 )
	{
		return TN_BLOCK_AES_192_CTR;
	}
	else if( strcmp(algo,"AES-256_CBC") == 0 || strcmp(algo ,"aes-256_cbc" ) == 0 )
	{
		return TN_BLOCK_AES_256_CBC;
	}
	else if( strcmp(algo,"AES-256_OFB") == 0 || strcmp(algo ,"aes-256_ofb" ) == 0 )
	{
		return TN_BLOCK_AES_256_OFB;
	}
	else if( strcmp(algo,"AES-256_CFB") == 0 || strcmp(algo ,"aes-256_cfb" ) == 0 )
	{
		return TN_BLOCK_AES_256_CFB;
	}
	else if( strcmp(algo,"AES-256_ECB") == 0 || strcmp(algo ,"aes-256_ecb" ) == 0 )
	{
		return TN_BLOCK_AES_256_ECB;
	}
	else if( strcmp(algo,"AES-256_CTR") == 0 || strcmp(algo ,"aes-256_ctr" ) == 0 )
	{
		return TN_BLOCK_AES_256_CTR;
	}
	else if( strcmp(algo,"LEA-128_CBC") == 0 || strcmp(algo ,"lea-128_cbc" ) == 0 )
	{
		return TN_BLOCK_LEA_128_CBC;
	}
	else if( strcmp(algo,"LEA-128_OFB") == 0 || strcmp(algo ,"lea-128_ofb" ) == 0 )
	{
		return TN_BLOCK_LEA_128_OFB;
	}
	else if( strcmp(algo,"LEA-128_CFB") == 0 || strcmp(algo ,"lea-128_cfb" ) == 0 )
	{
		return TN_BLOCK_LEA_128_CFB;
	}
	else if( strcmp(algo,"LEA-128_ECB") == 0 || strcmp(algo ,"lea-128_ecb" ) == 0 )
	{
		return TN_BLOCK_LEA_128_ECB;
	}
	else if( strcmp(algo,"LEA-128_CTR") == 0 || strcmp(algo ,"lea-128_ctr" ) == 0 )
	{
		return TN_BLOCK_LEA_128_CTR;
	}
	else if( strcmp(algo,"LEA-192_CBC") == 0 || strcmp(algo ,"lea-192_cbc" ) == 0 )
	{
		return TN_BLOCK_LEA_192_CBC;
	}
	else if( strcmp(algo,"LEA-192_OFB") == 0 || strcmp(algo ,"lea-192_ofb" ) == 0 )
	{
		return TN_BLOCK_LEA_192_OFB;
	}
	else if( strcmp(algo,"LEA-192_CFB") == 0 || strcmp(algo ,"lea-192_cfb" ) == 0 )
	{
		return TN_BLOCK_LEA_192_CFB;
	}
	else if( strcmp(algo,"LEA-192_ECB") == 0 || strcmp(algo ,"lea-192_ecb" ) == 0 )
	{
		return TN_BLOCK_LEA_192_ECB;
	}
	else if( strcmp(algo,"LEA-192_CTR") == 0 || strcmp(algo ,"lea-192_ctr" ) == 0 )
	{
		return TN_BLOCK_LEA_192_CTR;
	}
	else if( strcmp(algo,"LEA-256_CBC") == 0 || strcmp(algo ,"lea-256_cbc" ) == 0 )
	{
		return TN_BLOCK_LEA_256_CBC;
	}
	else if( strcmp(algo,"LEA-256_OFB") == 0 || strcmp(algo ,"lea-256_ofb" ) == 0 )
	{
		return TN_BLOCK_LEA_256_OFB;
	}
	else if( strcmp(algo,"LEA-256_CFB") == 0 || strcmp(algo ,"lea-256_cfb" ) == 0 )
	{
		return TN_BLOCK_LEA_256_CFB;
	}
	else if( strcmp(algo,"LEA-256_ECB") == 0 || strcmp(algo ,"lea-256_ecb" ) == 0 )
	{
		return TN_BLOCK_LEA_256_ECB;
	}
	else if( strcmp(algo,"LEA-256_CTR") == 0 || strcmp(algo ,"lea-256_ctr" ) == 0 )
	{
		return TN_BLOCK_LEA_256_CTR;
	}
	else
		return TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM;
}

int GetKeyIVLength(int nAlgoNID, int *nKeyLen, int *nIvLen)
{
	switch(nAlgoNID)
	{
		case TN_DIGEST_SHA256      :
		case TN_DIGEST_LSH256      :
			*nKeyLen = 32;
			*nIvLen = 0;
			break;
		case TN_DIGEST_SHA512      :
		case TN_DIGEST_LSH512      :
			*nKeyLen = 64;
			*nIvLen = 0;
			break;
		case TN_BLOCK_AES_128_ECB  :
		case TN_BLOCK_ARIA_128_ECB :
		case TN_BLOCK_SEED_ECB     :
		case TN_BLOCK_LEA_128_ECB  :

		case TN_BLOCK_SEED_CBC	   :
		case TN_BLOCK_SEED_OFB     :
		case TN_BLOCK_SEED_CFB     :
		case TN_BLOCK_SEED_CTR     :

		case TN_BLOCK_AES_128_CBC  :
		case TN_BLOCK_AES_128_CFB  :
		case TN_BLOCK_AES_128_OFB  :
		case TN_BLOCK_AES_128_CTR  :

		case TN_BLOCK_ARIA_128_CBC :
		case TN_BLOCK_ARIA_128_OFB :
		case TN_BLOCK_ARIA_128_CFB :
		case TN_BLOCK_ARIA_128_CTR :

		case TN_BLOCK_LEA_128_CBC  :
		case TN_BLOCK_LEA_128_OFB  :
		case TN_BLOCK_LEA_128_CFB  :
		case TN_BLOCK_LEA_128_CTR  :
			*nKeyLen = 16;
			*nIvLen = 16;
			break;

		case TN_BLOCK_AES_192_ECB  :
		case TN_BLOCK_ARIA_192_ECB :
		case TN_BLOCK_LEA_192_ECB  :

		case TN_BLOCK_AES_192_CBC  :
		case TN_BLOCK_AES_192_CFB  :
		case TN_BLOCK_AES_192_OFB  :
		case TN_BLOCK_AES_192_CTR  :

		case TN_BLOCK_ARIA_192_CBC :
		case TN_BLOCK_ARIA_192_OFB :
		case TN_BLOCK_ARIA_192_CFB :
		case TN_BLOCK_ARIA_192_CTR :

		case TN_BLOCK_LEA_192_CBC  :
		case TN_BLOCK_LEA_192_OFB  :
		case TN_BLOCK_LEA_192_CFB  :
		case TN_BLOCK_LEA_192_CTR  :
			*nKeyLen = 24;
			*nIvLen = 16;
			break;

		case TN_BLOCK_AES_256_ECB  :
		case TN_BLOCK_ARIA_256_ECB :
		case TN_BLOCK_LEA_256_ECB  :
		case TN_BLOCK_SEED_256_ECB :

		case TN_BLOCK_AES_256_CBC  :
		case TN_BLOCK_AES_256_CFB  :
		case TN_BLOCK_AES_256_OFB  :
		case TN_BLOCK_AES_256_CTR  :

		case TN_BLOCK_ARIA_256_CBC :
		case TN_BLOCK_ARIA_256_OFB :
		case TN_BLOCK_ARIA_256_CFB :
		case TN_BLOCK_ARIA_256_CTR :

		case TN_BLOCK_LEA_256_CBC  :
		case TN_BLOCK_LEA_256_OFB  :
		case TN_BLOCK_LEA_256_CFB  :
		case TN_BLOCK_LEA_256_CTR  :

		case TN_BLOCK_SEED_256_CBC :
		case TN_BLOCK_SEED_256_OFB :
		case TN_BLOCK_SEED_256_CFB :
		case TN_BLOCK_SEED_256_CTR :
			*nKeyLen = 32;
			*nIvLen = 16;
			break;
		default:
			return TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM;
			break;
	}

	return 0;
}

#ifndef DEVICE_MODE_TKS_CSTK

int TKS_CSTK_Make_KeyFromMaterial(UString *pMaterial, UString *pKey)
{
    int ret = 0, nHashAlgo = TKS_CSTK_DIGEST_SHA256;
    char sha256Val[TKS_CSTK_KEK_LEN] = {0,};
	TN_USTRING usOut;

	memset(&usOut, 0x00, sizeof(TN_USTRING));

    if(pMaterial->value == NULL || pMaterial->length == 0 || pKey == NULL)
    {
           ret = m_tkscstk_err_code = TK_CSTK_ERROR_MAKE_KEYFROMMATERIAL_ARG_EMPTY_OR_WRONG;
           goto err;
    }       

	usOut.value = NULL;
	ret = TCL_Digest(nHashAlgo, (TN_USTRING_PTR)pMaterial, &usOut);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

	if( TKS_CSTK_KEK_LEN != usOut.length)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_KEY_METERIAL_HASH_LENGTH_MISSMATCH;
		goto err;
	}

	usOut.value = (unsigned char*)calloc(usOut.length, sizeof(unsigned char));
	ret = TCL_Digest(nHashAlgo, (TN_USTRING_PTR)pMaterial, &usOut);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

    memcpy(sha256Val, usOut.value, usOut.length);

    // SHA256(in) 을 4,1,3,2 순서로 쪼개어 키로 만든다.
    memcpy(&pKey->value[0]	,	&sha256Val[24]	,8);
    memcpy(&pKey->value[8]	,	&sha256Val[0]	,8);
    memcpy(&pKey->value[16]	,	&sha256Val[16]	,8);
    memcpy(&pKey->value[24]	,	&sha256Val[8]	,8);
	pKey->length = usOut.length;

err:
	if(usOut.value != NULL) { free(usOut.value); usOut.value=NULL; }
    return ret;
}

int TKS_CSTK_GetKeyFromEncKey(int nAlgoNID, char *szKeyID, UString *usEncKey, UString *pKey)
{
	int ret;
	UString usMaterial, usKEK;
	TN_USTRING usKey, usIv, usDecKey;

	memset(&usMaterial, 0x00, sizeof(UString));
	memset(&usKEK, 0x00, sizeof(UString));
	memset(&usKey, 0x00, sizeof(TN_USTRING));
	memset(&usIv, 0x00, sizeof(TN_USTRING));
	memset(&usDecKey, 0x00, sizeof(TN_USTRING));

	usMaterial.length = strlen(szKeyID);
	usMaterial.value = (unsigned char*)szKeyID;

	usKEK.value = (unsigned char*)calloc(TKS_CSTK_KEK_LEN, sizeof(unsigned char));
	ret = TKS_CSTK_Make_KeyFromMaterial(&usMaterial, &usKEK);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

	usKey.length = TKS_CSTK_KEK_KEY_LEN;
	usKey.value = (unsigned char*)calloc(usKey.length, sizeof(unsigned char));
	memcpy(usKey.value, usKEK.value, usKey.length);
	usIv.length = TKS_CSTK_KEK_IV_LEN;
	usIv.value = (unsigned char*)calloc(usIv.length, sizeof(unsigned char));
	memcpy(usIv.value, usKEK.value + usKey.length, usIv.length);

	usDecKey.value = NULL;
	ret = ret = TCL_Block_Decrypt(nAlgoNID, (TN_USTRING*)usEncKey, &usKey, &usIv, &usDecKey);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

	usDecKey.value = (unsigned char*)calloc(usDecKey.length, sizeof(unsigned char));
	ret = ret = TCL_Block_Decrypt(nAlgoNID, (TN_USTRING*)usEncKey, &usKey, &usIv, &usDecKey);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

	if(pKey->value == NULL)
	{
 		ret = m_tkscstk_err_code = TK_CSTK_ERROR_TARGET_NOT_MEMORY_ALLOCATION;
        goto err;
	}

	memcpy(pKey->value, usDecKey.value, usDecKey.length);
	pKey->length = usDecKey.length;

err:
	if(usKEK.value != NULL) { free(usKEK.value); usKEK.value=NULL; }
	if(usDecKey.value != NULL) { free(usDecKey.value); usDecKey.value=NULL; }
	if(usKey.value != NULL) { free(usKey.value); usKey.value=NULL; }
	if(usIv.value != NULL) { free(usIv.value); usIv.value=NULL; }

	return ret;
}

#endif

/* TrustKeystore CS TK manage */
/*	
	Name : TrustKeystoreTK_Init
	Description: TrustKeystore ToolKit 초기화 함수
	Parameters
	[in/out] ppCtx : CSTK Context 구조체 
	[in] szConfPath : CSTK 설정파일 절대경로
	Return Value : 
	Note : 모든 툴킷 API 사용 전 호출
*/
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_Init(void **ppCtx, char * szConfPath)
#else
int TrustKeystoreTK_Init(void **ppCtx, char * szConfPath)
#endif
{
	int ret;

	if(ppCtx == NULL) 
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_CONTEXT_EMPTY_OR_WRONG;
		goto err;
	}

#ifdef GATEWAY_MODE_TKS_CSTK
	if(szConfPath == NULL || strlen(szConfPath) <= 0)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_CONF_PATH_EMPTY_OR_WRONG;
		goto err;
	}
#endif

#ifdef GATEWAY_MODE_TKS_CSTK
	ret = TrustKeystore_Init(ppCtx, szConfPath);
#else
	ret = TrustKeystore_Indirect_Init(ppCtx);
#endif
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

err:
	return ret;
}

/*	
	Name : TrustKeystoreTK_Final
	Description: TrustKeystore ToolKit Finalize 함수
	Parameters
	[in/out] ppCtx : CSTK Context 구조체 
	Return Value : 
	Note : 모든 툴킷 API 사용 후 호출
*/
#ifdef WIN32
TKSCSTK_API void TrustKeystoreTK_Final(void **ppCtx)
#else
void TrustKeystoreTK_Final(void **ppCtx)
#endif
{
#ifdef GATEWAY_MODE_TKS_CSTK
	TrustKeystore_Final(ppCtx);
#else
	TrustKeystore_Indirect_Final(ppCtx);
#endif
}

/* BLOCK Encryption & Decryption */
/*	
	Name : TrustKeystoreTK_Encipher
	Description: 대칭키 암호화 함수
	Parameters
	[in] pCtx : CSTK Context 구조체
	[in] szKeyID : 키 ID	 
	[in] in : 암호화 할 데이터 값과 길이
	[out] enc : 암호화 된 데이터 값과 길이
	Return Value : 성공일 경우 0, 실패일 경우 에러코드 값
	Note : 
*/
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_Encipher(void *pCtx, char *szKeyID, UString *in, UString *enc)
#else
int TrustKeystoreTK_Encipher(void *pCtx, char *szKeyID, UString *in, UString *enc)
#endif
{
	int ret, nKeyIvLen, nAlgoNID, nKeyLen, nIvLen, nEncKeyIvLen, nRecKeyIvLen, nKEKAlgo = TN_BLOCK_AES_128_CBC;
	unsigned char *pKeyIv=NULL, *pRecKeyIv = NULL;
	unsigned char ECB_IV[16] = {0x00, };
	char *szKeyAlgo=NULL, *szKeyOPMode=NULL;
	char szAlgoInfo[50] = {0,};
	TN_USTRING usKey, usIv, usIN, usOut;
	UString usEncKey, usDecKey;

	memset(&usKey, 0x00, sizeof(TN_USTRING));
	memset(&usIv, 0x00, sizeof(TN_USTRING));
	memset(&usIN, 0x00, sizeof(TN_USTRING));
	memset(&usOut, 0x00, sizeof(TN_USTRING));
	memset(szAlgoInfo, 0x00, sizeof(szAlgoInfo));
	memset(&usEncKey, 0x00, sizeof(UString));
	memset(&usDecKey, 0x00, sizeof(UString));

	if(pCtx == NULL)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_CONTEXT_EMPTY_OR_WRONG;
		goto err;
	}

	if(szKeyID == NULL || strlen(szKeyID) <= 0)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_KEYID_EMPTY_OR_WRONG;
		goto err;
	}
	
#ifdef GATEWAY_MODE_TKS_CSTK
	ret = TrustKeystore_GetKeyAlgo(pCtx, szKeyID, &szKeyAlgo);
#else
	ret = TrustKeystore_Indirect_GetKeyAlgo(pCtx, szKeyID, &szKeyAlgo);
#endif
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}
	
#ifdef GATEWAY_MODE_TKS_CSTK
	ret = TrustKeystore_GetKeyOPMode(pCtx, szKeyID, &szKeyOPMode);
#else
	ret = TrustKeystore_Indirect_GetKeyOPMode(pCtx, szKeyID, &szKeyOPMode);
#endif
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

	if( sizeof(szAlgoInfo) < ( strlen(szKeyAlgo) + strlen(szKeyOPMode) + 1 ) ) 
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_TARGET_BUFFER_TOO_SMALL;
		goto err;
	}	

	sprintf(szAlgoInfo, "%s_%s", szKeyAlgo, szKeyOPMode);

	nAlgoNID = GetCipherIDByChar(szAlgoInfo);
	if(nAlgoNID == TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM;
		goto err;
	}

#ifdef LIGHTWEIGHT_TKS_CSTK
	if(nAlgoNID != TN_BLOCK_LEA_128_CFB)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_LIGHTWEIGHT_MODE_UNSUPPORTED_ALGORITHM;
		goto err;
	}
#endif

	ret = GetKeyIVLength(nAlgoNID, &nKeyLen, &nIvLen);
	if(ret  == TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM;
		goto err;
	}

#ifndef DEVICE_MODE_TKS_CSTK

#ifdef LIGHTWEIGHT_TKS_CSTK
	ret = TrustKeystore_GetKey(pCtx, szKeyID, (char**)&pRecKeyIv, &nRecKeyIvLen);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}
	nKeyIvLen = nRecKeyIvLen;
	pKeyIv = (unsigned char*)calloc(nKeyIvLen, sizeof(unsigned char));
	memcpy(pKeyIv, pRecKeyIv, nKeyIvLen);	
#else
	ret = TrustKeystore_GetEncKey(pCtx, szKeyID, (char**)&pRecKeyIv, &nRecKeyIvLen);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}	

	usEncKey.length = nRecKeyIvLen;
	usEncKey.value = pRecKeyIv;

	usDecKey.value = (unsigned char*)calloc( nKeyLen + nIvLen, sizeof(unsigned char));
	ret = TKS_CSTK_GetKeyFromEncKey(nKEKAlgo, szKeyID, &usEncKey, &usDecKey);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}	

	nKeyIvLen = usDecKey.length;
	pKeyIv = (unsigned char*)calloc(nKeyIvLen, sizeof(unsigned char));
	memcpy(pKeyIv, usDecKey.value, nKeyIvLen);
#endif

#else
	ret = TrustKeystore_Indirect_GetKey(pCtx, szKeyID, &pRecKeyIv, &nRecKeyIvLen);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}	
	nKeyIvLen = nRecKeyIvLen;
	pKeyIv = (unsigned char*)calloc(nKeyIvLen, sizeof(unsigned char));
	memcpy(pKeyIv, pRecKeyIv, nKeyIvLen);	
#endif

	if( nKeyIvLen != (nKeyLen + nIvLen) )
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_KEY_IV_LENGTH_MISSMATCH;
		goto err;
	}

	usKey.value = (unsigned char*)calloc(nKeyLen, sizeof(unsigned char));
	usIv.value = (unsigned char*)calloc(nIvLen, sizeof(unsigned char));
	usKey.length = nKeyLen;
	usIv.length = nIvLen;

	memcpy(usKey.value, pKeyIv, nKeyLen);
	
	switch(nAlgoNID)
	{
		case TN_BLOCK_AES_128_ECB  :
		case TN_BLOCK_ARIA_128_ECB :
		case TN_BLOCK_SEED_ECB     :
		case TN_BLOCK_LEA_128_ECB  :
		case TN_BLOCK_AES_192_ECB  :
		case TN_BLOCK_ARIA_192_ECB :
		case TN_BLOCK_LEA_192_ECB  :
		case TN_BLOCK_AES_256_ECB  :
		case TN_BLOCK_ARIA_256_ECB :
		case TN_BLOCK_LEA_256_ECB  :
		case TN_BLOCK_SEED_256_ECB :	
			memcpy(usIv.value, ECB_IV, nIvLen);
			break;
		default :
			memcpy(usIv.value, pKeyIv+nKeyLen, nIvLen);
			break;
	}

	ret = TCL_Block_Encrypt(nAlgoNID, (TN_USTRING_PTR) in, &usKey, &usIv, &usOut);
	if(ret)
	{
#ifdef LIGHTWEIGHT_TKS_CSTK
		if( (ret & 0x00000fff) == TNR_BLOCK_ALGO_NID_NOT_SUPPORTED )
		{
			m_tkscstk_err_code = TK_CSTK_ERROR_LIGHTWEIGHT_MODE_UNSUPPORTED_ALGORITHM;
		}
#else
		m_tkscstk_err_code = ret;
#endif
		goto err;
	}

	if(enc->value == NULL)
	{
		enc->length = usOut.length;
		ret = m_tkscstk_err_code = TK_CSTK_SUCCESS;
		goto err;
	}

	usOut.value = (unsigned char*)calloc(enc->length, sizeof(unsigned char));
	ret = TCL_Block_Encrypt(nAlgoNID, (TN_USTRING_PTR) in, &usKey, &usIv, &usOut);
	if(ret)
	{
#ifdef LIGHTWEIGHT_TKS_CSTK
		if( (ret & 0x00000fff) == TNR_BLOCK_ALGO_NID_NOT_SUPPORTED )
		{
			m_tkscstk_err_code = TK_CSTK_ERROR_LIGHTWEIGHT_MODE_UNSUPPORTED_ALGORITHM;
		}
#else
		m_tkscstk_err_code = ret;
#endif
		goto err;
	}

	memcpy(enc->value, usOut.value, usOut.length);
err:
	if(pRecKeyIv != NULL) TrustKeystore_MemFree(&pRecKeyIv); 
	if(pKeyIv != NULL) { free(pKeyIv); pKeyIv=NULL; }
	if(usKey.value != NULL) { free(usKey.value); memset(&usKey, 0x00, sizeof(TN_USTRING)); }
	if(usIv.value != NULL) { free(usIv.value); memset(&usIv, 0x00, sizeof(TN_USTRING)); }
	if(usOut.value != NULL) { free(usOut.value); memset(&usOut, 0x00, sizeof(TN_USTRING)); }
	if(usDecKey.value != NULL) { free(usDecKey.value); memset(&usDecKey, 0x00, sizeof(UString)); }
	if(szKeyAlgo != NULL) TrustKeystore_MemFree(&szKeyAlgo);
	if(szKeyOPMode != NULL) TrustKeystore_MemFree(&szKeyOPMode);

	return ret ;
}

/*	
	Name : TrustKeystoreTK_Decrypt
	Description: 대칭키 복호화 함수
	Parameters
	[in] pCtx : CSTK Context 구조체
	[in] szKeyID : 키 ID	 
	[in] enc : 암호화 된 데이터 값과 길이
	[out] dec : 복호화 된 데이터 값과 길이
	Return Value : 성공일 경우 0, 실패일 경우 에러코드 값
	Note : 
*/
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_Decrypt(void *pCtx, char *szKeyID, UString *enc, UString *dec)
#else
int TrustKeystoreTK_Decrypt(void *pCtx, char *szKeyID, UString *enc, UString *dec)
#endif
{
	int ret, nKeyIvLen, nAlgoNID, nKeyLen, nIvLen, nRecKeyIvLen, nKEKAlgo = TN_BLOCK_AES_128_CBC;
	unsigned char *pKeyIv=NULL, *pRecKeyIv = NULL;
	unsigned char ECB_IV[16] = {0x00, };
	char *szKeyAlgo=NULL, *szKeyOPMode=NULL;
	char szAlgoInfo[50] = {0,};
	TN_USTRING usKey, usIv, usIN, usOut;
	UString usEncKey, usDecKey;

	memset(&usKey, 0x00, sizeof(TN_USTRING));
	memset(&usIv, 0x00, sizeof(TN_USTRING));
	memset(&usIN, 0x00, sizeof(TN_USTRING));
	memset(&usOut, 0x00, sizeof(TN_USTRING));
	memset(szAlgoInfo, 0x00, sizeof(szAlgoInfo));
	memset(&usEncKey, 0x00, sizeof(UString));
	memset(&usDecKey, 0x00, sizeof(UString));

	if(pCtx == NULL)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_CONTEXT_EMPTY_OR_WRONG;
		goto err;
	}

	if(szKeyID == NULL || strlen(szKeyID) <= 0)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_KEYID_EMPTY_OR_WRONG;
		goto err;
	}
	
#ifdef GATEWAY_MODE_TKS_CSTK
	ret = TrustKeystore_GetKeyAlgo(pCtx, szKeyID, &szKeyAlgo);
#else
	ret = TrustKeystore_Indirect_GetKeyAlgo(pCtx, szKeyID, &szKeyAlgo);
#endif
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

#ifdef GATEWAY_MODE_TKS_CSTK
	ret = TrustKeystore_GetKeyOPMode(pCtx, szKeyID, &szKeyOPMode);
#else
	ret = TrustKeystore_Indirect_GetKeyOPMode(pCtx, szKeyID, &szKeyOPMode);
#endif
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

	if( sizeof(szAlgoInfo) < ( strlen(szKeyAlgo) + strlen(szKeyOPMode) + 1 ) ) 
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_TARGET_BUFFER_TOO_SMALL;
		goto err;
	}	

	sprintf(szAlgoInfo, "%s_%s", szKeyAlgo, szKeyOPMode);

	nAlgoNID = GetCipherIDByChar(szAlgoInfo);
	if(nAlgoNID == TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM;
		goto err;
	}

#ifdef LIGHTWEIGHT_TKS_CSTK
	if(nAlgoNID != TN_BLOCK_LEA_128_CFB)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_LIGHTWEIGHT_MODE_UNSUPPORTED_ALGORITHM;
		goto err;
	}
#endif

	ret = GetKeyIVLength(nAlgoNID, &nKeyLen, &nIvLen);
	if(ret  == TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM;
		goto err;
	}	

#ifndef DEVICE_MODE_TKS_CSTK

#ifdef LIGHTWEIGHT_TKS_CSTK
	ret = TrustKeystore_GetKey(pCtx, szKeyID, (char**)&pRecKeyIv, &nRecKeyIvLen);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}
	nKeyIvLen = nRecKeyIvLen;
	pKeyIv = (unsigned char*)calloc(nKeyIvLen, sizeof(unsigned char));
	memcpy(pKeyIv, pRecKeyIv, nKeyIvLen);	
#else
	ret = TrustKeystore_GetEncKey(pCtx, szKeyID, (char**)&pRecKeyIv, &nRecKeyIvLen);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}	

	usEncKey.length = nRecKeyIvLen;
	usEncKey.value = pRecKeyIv;

	usDecKey.value = (unsigned char*)calloc( nKeyLen + nIvLen, sizeof(unsigned char));
	ret = TKS_CSTK_GetKeyFromEncKey(nKEKAlgo, szKeyID, &usEncKey, &usDecKey);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}	

	nKeyIvLen = usDecKey.length;
	pKeyIv = (unsigned char*)calloc(nKeyIvLen, sizeof(unsigned char));
	memcpy(pKeyIv, usDecKey.value, nKeyIvLen);
#endif

#else
	ret = TrustKeystore_Indirect_GetKey(pCtx, szKeyID, &pRecKeyIv, &nRecKeyIvLen);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}	
	nKeyIvLen = nRecKeyIvLen;
	pKeyIv = (unsigned char*)calloc(nKeyIvLen, sizeof(unsigned char));
	memcpy(pKeyIv, pRecKeyIv, nKeyIvLen);
#endif

	if( nKeyIvLen != (nKeyLen + nIvLen))
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_KEY_IV_LENGTH_MISSMATCH;
		goto err;
	}

	usKey.value = (unsigned char*)calloc(nKeyLen, sizeof(unsigned char));
	usIv.value = (unsigned char*)calloc(nIvLen, sizeof(unsigned char));
	usKey.length = nKeyLen;
	usIv.length = nIvLen;

	memcpy(usKey.value, pKeyIv, nKeyLen);
	
	switch(nAlgoNID)
	{
		case TN_BLOCK_AES_128_ECB  :
		case TN_BLOCK_ARIA_128_ECB :
		case TN_BLOCK_SEED_ECB     :
		case TN_BLOCK_LEA_128_ECB  :
		case TN_BLOCK_AES_192_ECB  :
		case TN_BLOCK_ARIA_192_ECB :
		case TN_BLOCK_LEA_192_ECB  :
		case TN_BLOCK_AES_256_ECB  :
		case TN_BLOCK_ARIA_256_ECB :
		case TN_BLOCK_LEA_256_ECB  :
		case TN_BLOCK_SEED_256_ECB :	
			memcpy(usIv.value, ECB_IV, nIvLen);
			break;
		default :
			memcpy(usIv.value, pKeyIv+nKeyLen, nIvLen);
			break;
	}

	usIN.length = enc->length;
	usIN.value = enc->value;

	ret = TCL_Block_Decrypt(nAlgoNID, &usIN, &usKey, &usIv, &usOut);
	if(ret)
	{
#ifdef LIGHTWEIGHT_TKS_CSTK
		if( (ret & 0x00000fff) == TNR_BLOCK_ALGO_NID_NOT_SUPPORTED )
		{
			m_tkscstk_err_code = TK_CSTK_ERROR_LIGHTWEIGHT_MODE_UNSUPPORTED_ALGORITHM;
		}
#else
		m_tkscstk_err_code = ret;
#endif
		goto err;
	}

	if(dec->value == NULL)
	{
		dec->length = usOut.length;
		ret = m_tkscstk_err_code = TK_CSTK_SUCCESS;
		goto err;
	}

	usOut.value = (unsigned char*)calloc(dec->length, sizeof(unsigned char));
	ret = TCL_Block_Decrypt(nAlgoNID, (TN_USTRING_PTR) enc, &usKey, &usIv, &usOut);
	if(ret)
	{
#ifdef LIGHTWEIGHT_TKS_CSTK
		if( (ret & 0x00000fff) == TNR_BLOCK_ALGO_NID_NOT_SUPPORTED )
		{
			m_tkscstk_err_code = TK_CSTK_ERROR_LIGHTWEIGHT_MODE_UNSUPPORTED_ALGORITHM;
		}
#else
		m_tkscstk_err_code = ret;
#endif
		goto err;
	}

	memcpy(dec->value, usOut.value, usOut.length);
	dec->length = usOut.length;
err:
	if(pRecKeyIv != NULL) TrustKeystore_MemFree(&pRecKeyIv);
	if(pKeyIv != NULL) { free(pKeyIv); pKeyIv=NULL; }
	if(usKey.value != NULL) { free(usKey.value); memset(&usKey, 0x00, sizeof(TN_USTRING)); }
	if(usIv.value != NULL) { free(usIv.value); memset(&usIv, 0x00, sizeof(TN_USTRING)); }
	if(usOut.value != NULL) { free(usOut.value); memset(&usOut, 0x00, sizeof(TN_USTRING)); }
	if(usDecKey.value != NULL) { free(usDecKey.value); memset(&usDecKey, 0x00, sizeof(UString)); }
	if(szKeyAlgo != NULL) TrustKeystore_MemFree(&szKeyAlgo);
	if(szKeyOPMode != NULL) TrustKeystore_MemFree(&szKeyOPMode);

	return ret ;
}

/* Message Digest */
/*	
	Name : TrustKeystoreTK_Hash
	Description: 메시지 축소 생성 함수
	Parameters
	[in] nHashAlgo : 메시지축소 알고리즘 NID
	[in] in : 메시지 축소 할 데이터 값과 길이
	[out] out : 메시지 축소 된 데이터 값과 길이
	Return Value : 성공일 경우 0, 실패일 경우 에러코드 값
	Note : 
*/
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_Hash(int nHashAlgo, UString *in, UString *out)
#else
int TrustKeystoreTK_Hash(int nHashAlgo, UString *in, UString *out)
#endif
{
	int ret;
	TN_USTRING usIN, usOut;

	memset(&usIN, 0x00, sizeof(TN_USTRING));
	memset(&usOut, 0x00, sizeof(TN_USTRING));

	usIN.length = in->length;
	usIN.value = in->value;

	usOut.value = NULL;
	ret = TCL_Digest(nHashAlgo, &usIN, &usOut);
	if(ret)
	{
#ifdef LIGHTWEIGHT_TKS_CSTK
		if( (ret & 0x00000fff) == TNR_DIGEST_TYPE_NOT_SUPPORTED )
		{
			m_tkscstk_err_code = TK_CSTK_ERROR_LIGHTWEIGHT_MODE_UNSUPPORTED_ALGORITHM;
		}
#else
		m_tkscstk_err_code = ret;
#endif
		goto err;
	}

	if(out->value == NULL)
	{
		out->length = usOut.length;
		ret = m_tkscstk_err_code = TK_CSTK_SUCCESS;
		goto err;
	}

	usOut.value = (unsigned char*)calloc(usOut.length, sizeof(unsigned char));
	ret = TCL_Digest(nHashAlgo, &usIN, &usOut);
	if(ret)
	{
#ifdef LIGHTWEIGHT_TKS_CSTK
		if( (ret & 0x00000fff) == TNR_DIGEST_TYPE_NOT_SUPPORTED )
		{
			m_tkscstk_err_code = TK_CSTK_ERROR_LIGHTWEIGHT_MODE_UNSUPPORTED_ALGORITHM;
		}
#else
		m_tkscstk_err_code = ret;
#endif
		goto err;
	}

	memcpy(out->value, usOut.value, usOut.length);
	out->length = usOut.length;

err:
	if(usOut.value != NULL) { free(usOut.value); memset(&usOut, 0x00, sizeof(TN_USTRING)); }

	return ret;
}


/* Message Authentication Code */
/*	
	Name : TrustKeystoreTK_GenerateHMAC
	Description: 메시지인증코드 생성 함수
	Parameters
	[in] pCtx : CSTK Context 구조체
	[in] szKeyID : 키 ID
	[in] in : 메시지 축소 할 데이터 값과 길이
	[out] out : 메시지 축소 된 데이터 값과 길이
	Return Value : 성공일 경우 0, 실패일 경우 에러코드 값
	Note : 
*/
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_GenerateHMAC(void *pCtx, char *szKeyID, UString *in, UString *out)
#else
int TrustKeystoreTK_GenerateHMAC(void *pCtx, char *szKeyID, UString *in, UString *out)
#endif
{
	int ret, nAlgoNID, nKeyLen, nIvLen, nKeyIvLen, nRecKeyIvLen, nKEKAlgo=TN_BLOCK_AES_128_CBC;
	unsigned char *pKeyIv=NULL, *pRecKeyIv=NULL;
	char *szKeyAlgo = NULL, *szKeyOPMode = NULL;
	char szAlgoInfo[50] = {0,};
	TN_USTRING usKey, usIN, usOut;
	UString usEncKey, usDecKey;

	memset(&usKey, 0x00, sizeof(TN_USTRING));
	memset(&usIN, 0x00, sizeof(TN_USTRING));
	memset(&usOut, 0x00, sizeof(TN_USTRING));
	memset(szAlgoInfo, 0x00, sizeof(szAlgoInfo));
	memset(&usEncKey, 0x00, sizeof(UString));
	memset(&usDecKey, 0x00, sizeof(UString));

#ifdef LIGHTWEIGHT_TKS_CSTK
	ret = m_tkscstk_err_code = TK_CSTK_ERROR_LIGHTWEIGHT_MODE_UNSUPPORTED_API;
	goto err;
#else
	if(pCtx == NULL)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_CONTEXT_EMPTY_OR_WRONG;
		goto err;
	}

	if(szKeyID == NULL || strlen(szKeyID) <= 0)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_KEYID_EMPTY_OR_WRONG;
		goto err;
	}

#ifndef LIGHTWEIGHT_TKS_CSTK

#ifdef GATEWAY_MODE_TKS_CSTK
	ret = TrustKeystore_GetKeyAlgo(pCtx, szKeyID, &szKeyAlgo);
#else
	ret = TrustKeystore_Indirect_GetKeyAlgo(pCtx, szKeyID, &szKeyAlgo);
#endif
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

#ifdef GATEWAY_MODE_TKS_CSTK
	ret = TrustKeystore_GetKeyOPMode(pCtx, szKeyID, &szKeyOPMode);
#else
	ret = TrustKeystore_Indirect_GetKeyOPMode(pCtx, szKeyID, &szKeyOPMode);
#endif
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

	if( sizeof(szAlgoInfo) < ( strlen(szKeyAlgo) + strlen(szKeyOPMode) + 1 ) ) 
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_TARGET_BUFFER_TOO_SMALL;
		goto err;
	}	

	sprintf(szAlgoInfo, "%s", szKeyAlgo);

	nAlgoNID = GetCipherIDByChar(szAlgoInfo);
	if(nAlgoNID == TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM;
		goto err;
	}
#else
	nAlgoNID = TN_DIGEST_LSH256;
#endif

	ret = GetKeyIVLength(nAlgoNID, &nKeyLen, &nIvLen);
	if(ret  == TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM;
		goto err;
	}	

#ifndef DEVICE_MODE_TKS_CSTK

#ifdef LIGHTWEIGHT_TKS_CSTK
	ret = TrustKeystore_GetKey(pCtx, szKeyID, (char**)&pRecKeyIv, &nRecKeyIvLen);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}
	nKeyIvLen = nRecKeyIvLen;
	pKeyIv = (unsigned char*)calloc(nKeyIvLen, sizeof(unsigned char));
	memcpy(pKeyIv, pRecKeyIv, nKeyIvLen);	
#else
	ret = TrustKeystore_GetEncKey(pCtx, szKeyID, (char**)&pRecKeyIv, &nRecKeyIvLen);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}	

	usEncKey.length = nRecKeyIvLen;
	usEncKey.value = pRecKeyIv;

	usDecKey.value = (unsigned char*)calloc( nKeyLen + nIvLen, sizeof(unsigned char));
	ret = TKS_CSTK_GetKeyFromEncKey(nKEKAlgo, szKeyID, &usEncKey, &usDecKey);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}	

	nKeyIvLen = usDecKey.length;
	pKeyIv = (unsigned char*)calloc(nKeyIvLen, sizeof(unsigned char));
	memcpy(pKeyIv, usDecKey.value, nKeyIvLen);
#endif

#else
	ret = TrustKeystore_Indirect_GetKey(pCtx, szKeyID, &pRecKeyIv, &nRecKeyIvLen);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}	
	nKeyIvLen = nRecKeyIvLen;
	pKeyIv = (unsigned char*)calloc(nKeyIvLen, sizeof(unsigned char));
	memcpy(pKeyIv, pRecKeyIv, nKeyIvLen);
#endif

	if( nKeyIvLen != (nKeyLen + nIvLen))
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_KEY_IV_LENGTH_MISSMATCH;
		goto err;
	}

	usKey.value = (unsigned char*)calloc(nKeyLen, sizeof(unsigned char));
	usKey.length = nKeyLen;

	memcpy(usKey.value, pKeyIv, nKeyLen);

	usOut.value = NULL;
	ret = TCL_HMAC(nAlgoNID, &usKey, &usIN, &usOut);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

	if(out->value == NULL)
	{
		out->length = usOut.length;
		ret = m_tkscstk_err_code = TK_CSTK_SUCCESS;
		goto err;
	}

	usOut.value = (unsigned char*)calloc(usOut.length, sizeof(unsigned char));
	if(!usOut.value)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

	ret = TCL_HMAC(nAlgoNID, &usKey, &usIN, &usOut);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

	memcpy(out->value, usOut.value, usOut.length);
	out->length = usOut.length;

#endif

err:
	if(pRecKeyIv != NULL) TrustKeystore_MemFree(&pRecKeyIv);
	if(pKeyIv != NULL) { free(pKeyIv); pKeyIv=NULL; }
	if(usKey.value != NULL) { free(usKey.value); memset(&usKey, 0x00, sizeof(TN_USTRING)); }
	if(usOut.value != NULL) { free(usOut.value); memset(&usOut, 0x00, sizeof(TN_USTRING)); }
	if(usDecKey.value != NULL) { free(usDecKey.value); memset(&usDecKey, 0x00, sizeof(UString)); }
	if(szKeyAlgo != NULL) TrustKeystore_MemFree(&szKeyAlgo);
	if(szKeyOPMode != NULL) TrustKeystore_MemFree(&szKeyOPMode);
	return ret;
}

/* TKS CSTK KeyMsg...Request & Response & Set API */
/*	
	Name : TrustKeystoreTK_MakeRequestKeyMsg
	Description: GateWay에 필요한 키를 요청하는 키요청 메시지 생성 함수
	Parameters
	[in] pCtx : CSTK Context 구조체
	[in] szDeviceID : 요청하는 Device의 ID
	[in] szKeyID : 키 ID
	[out] usRequestMsg : 키요청 메시지의 데이터 값과 길이
	Return Value : 성공일 경우 0, 실패일 경우 에러코드 값
	Note : GateWay CSTK에서는 지원하지 않는 함수이다.
*/
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_MakeRequestKeyMsg(void *pCtx, char *szDeviceID, char *szKeyID, UString *usRequestMsg)
#else
int TrustKeystoreTK_MakeRequestKeyMsg(void *pCtx, char *szDeviceID, char *szKeyID, UString *usRequestMsg)
#endif
{
	int ret, ReqMsgLen=0;
	char *szReqMsg=NULL;

#if defined (DEVICE_MODE_TKS_CSTK) || (BOTH_MODE_TKS_CSTK)
	ret = TrustKeystore_Indirect_MakeRequestKeyMsg(pCtx, szDeviceID, szKeyID, &szReqMsg, &ReqMsgLen);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

	if(usRequestMsg->value == NULL)
	{
		usRequestMsg->length = ReqMsgLen;
		ret = m_tkscstk_err_code = TK_CSTK_SUCCESS;
		goto err;
	}

	ret = TrustKeystore_Indirect_MakeRequestKeyMsg(pCtx, szDeviceID, szKeyID, &szReqMsg, &ReqMsgLen);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

	memcpy(usRequestMsg->value, szReqMsg, ReqMsgLen);
	usRequestMsg->length = ReqMsgLen;
#else
	ret = m_tkscstk_err_code = TK_CSTK_ERROR_GATEWAY_MODE_UNSUPPORTED_API;
	goto err;
#endif

err:
	if(szReqMsg != NULL) { TrustKeystore_MemFree(&szReqMsg); szReqMsg = NULL; }

	return ret;
}

/*	
	Name : TrustKeystoreTK_MakeResponseKeyMsg
	Description: Device에 요청한 키정보를 전달하는 키반환 메시지 생성 함수
	Parameters
	[in] pCtx : CSTK Context 구조체
	[in] szDeviceID : 키정보 메시지를 전달하는 Gateway의 ID
	[in] usRequestMsg : 키요청 메시지의 데이터 값과 길이
	[out] usResponseMsg : 키반환 메시지의 데이터 값과 길이
	Return Value : 성공일 경우 0, 실패일 경우 에러코드 값
	Note : Device CSTK에서는 지원하지 않는 함수이다.
*/
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_MakeResponseKeyMsg(void *pCtx, char *szDeviceID, UString *usRequestMsg, UString *usResponseMsg)
#else
int TrustKeystoreTK_MakeResponseKeyMsg(void *pCtx, char *szDeviceID, UString *usRequestMsg, UString *usResponseMsg)
#endif
{
	int ret, ResMsgLen=0;
	char *szResMsg=NULL;

#if defined (GATEWAY_MODE_TKS_CSTK) || (BOTH_MODE_TKS_CSTK)
	ret = TrustKeystore_Indirect_MakeResponseKeyMsg(pCtx, szDeviceID, (char*)usRequestMsg->value, usRequestMsg->length, &szResMsg, &ResMsgLen);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

	if(usResponseMsg->value == NULL)
	{
		usResponseMsg->length = ResMsgLen;
		ret = m_tkscstk_err_code = TK_CSTK_SUCCESS;
		goto err;
	}

	ret = TrustKeystore_Indirect_MakeResponseKeyMsg(pCtx, szDeviceID, (char*)usRequestMsg->value, usRequestMsg->length, &szResMsg, &ResMsgLen);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

	memcpy(usResponseMsg->value, szResMsg, ResMsgLen);
	usResponseMsg->length = ResMsgLen;
#else
	ret = m_tkscstk_err_code = TK_CSTK_ERROR_DEVICE_MODE_UNSUPPORTED_API;
	goto err;
#endif

err:
	if(szResMsg != NULL) { TrustKeystore_MemFree(&szResMsg); szResMsg = NULL; }

	return ret;
}

/*	
	Name : TrustKeystoreTK_SetKey
	Description: 전달받은 키반환 메시지를 저장하는 함수
	Parameters
	[in] pCtx : CSTK Context 구조체
	[in] usResponseMsg : 키반환 메시지의 데이터 값과 길이
	Return Value : 성공일 경우 0, 실패일 경우 에러코드 값
	Note : Gateway CSTK에서는 지원하지 않는 함수이다.
*/
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_SetKey(void *pCtx, UString *usResponseMsg)
#else
int TrustKeystoreTK_SetKey(void *pCtx, UString *usResponseMsg)
#endif
{
	int ret;
#if defined (DEVICE_MODE_TKS_CSTK) || (BOTH_MODE_TKS_CSTK)
	ret = TrustKeystore_Indirect_SetKey(pCtx, (char*)usResponseMsg->value, usResponseMsg->length);
	m_tkscstk_err_code = ret;
#else
	ret = m_tkscstk_err_code = TK_CSTK_ERROR_GATEWAY_MODE_UNSUPPORTED_API;
	goto err;
#endif

err:
	return ret;
}

/*	
	Name : TrustKeystoreTK_GetKey
	Description: 필요한 키를 추출 하는 함수
	Parameters
	[in] pCtx : CSTK Context 구조체
	[in] szKeyID : 키 ID
	[out] usKeyIv : 키와초키벡터의 데이터 값과 길이
	Return Value : 성공일 경우 0, 실패일 경우 에러코드 값
	Note : Device CSTK에서는 지원하지 않는 함수이다.
*/
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_GetKey(void *pCtx, char *szKeyID, UString *usKeyIv)
#else
int TrustKeystoreTK_GetKey(void *pCtx, char *szKeyID, UString *usKeyIv)
#endif
{
	int ret, nKeyIvLen, nAlgoNID, nKeyLen, nIvLen, nEncKeyIvLen, nRecKeyIvLen, nKEKAlgo = TN_BLOCK_AES_128_CBC;
	unsigned char *pKeyIv=NULL, *pRecKeyIv = NULL;
	char *szKeyAlgo=NULL, *szKeyOPMode=NULL;
	char szAlgoInfo[50] = {0,};
	UString usEncKey, usDecKey;

	memset(szAlgoInfo, 0x00, sizeof(szAlgoInfo));
	memset(&usEncKey, 0x00, sizeof(UString));
	memset(&usDecKey, 0x00, sizeof(UString));

	if(pCtx == NULL)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_CONTEXT_EMPTY_OR_WRONG;
		goto err;
	}

	if(szKeyID == NULL || strlen(szKeyID) <= 0)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_KEYID_EMPTY_OR_WRONG;
		goto err;
	}

#ifdef GATEWAY_MODE_TKS_CSTK
	ret = TrustKeystore_GetKeyAlgo(pCtx, szKeyID, &szKeyAlgo);
#else
	ret = TrustKeystore_Indirect_GetKeyAlgo(pCtx, szKeyID, &szKeyAlgo);
#endif
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

#ifdef GATEWAY_MODE_TKS_CSTK
	ret = TrustKeystore_GetKeyOPMode(pCtx, szKeyID, &szKeyOPMode);
#else
	ret = TrustKeystore_Indirect_GetKeyOPMode(pCtx, szKeyID, &szKeyOPMode);
#endif
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}

	if( sizeof(szAlgoInfo) < ( strlen(szKeyAlgo) + strlen(szKeyOPMode) + 1 ) ) 
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_TARGET_BUFFER_TOO_SMALL;
		goto err;
	}	
	////
	printf("szKeyAlgo : [%s], szKeyOPMode : [%s]\n", szKeyAlgo, szKeyOPMode);
	////
	if( (szKeyOPMode != NULL) && (strlen(szKeyOPMode) > 0) )
		sprintf(szAlgoInfo, "%s_%s", szKeyAlgo, szKeyOPMode);
	else
		sprintf(szAlgoInfo, "%s", szKeyAlgo);
	////
	printf("szAlgoInfo : [%s]\n", szAlgoInfo);
	////
	nAlgoNID = GetCipherIDByChar(szAlgoInfo);
	if(nAlgoNID == TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM;
		goto err;
	}

	ret = GetKeyIVLength(nAlgoNID, &nKeyLen, &nIvLen);
	if(ret  == TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM)
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM;
		goto err;
	}

#ifndef DEVICE_MODE_TKS_CSTK

#ifdef LIGHTWEIGHT_TKS_CSTK
	ret = TrustKeystore_GetKey(pCtx, szKeyID, (char**)&pRecKeyIv, &nRecKeyIvLen);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}
	nKeyIvLen = nRecKeyIvLen;
	pKeyIv = (unsigned char*)calloc(nKeyIvLen, sizeof(unsigned char));
	memcpy(pKeyIv, pRecKeyIv, nKeyIvLen);	
#else
	ret = TrustKeystore_GetEncKey(pCtx, szKeyID, (char**)&pRecKeyIv, &nRecKeyIvLen);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}	

	usEncKey.length = nRecKeyIvLen;
	usEncKey.value = pRecKeyIv;

	usDecKey.value = (unsigned char*)calloc( nKeyLen + nIvLen, sizeof(unsigned char));
	ret = TKS_CSTK_GetKeyFromEncKey(nKEKAlgo, szKeyID, &usEncKey, &usDecKey);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}	

	nKeyIvLen = usDecKey.length;
	pKeyIv = (unsigned char*)calloc(nKeyIvLen, sizeof(unsigned char));
	memcpy(pKeyIv, usDecKey.value, nKeyIvLen);
#endif

#else
	ret = TrustKeystore_Indirect_GetKey(pCtx, szKeyID, &pRecKeyIv, &nRecKeyIvLen);
	if(ret)
	{
		m_tkscstk_err_code = ret;
		goto err;
	}	
	nKeyIvLen = nRecKeyIvLen;
	pKeyIv = (unsigned char*)calloc(nKeyIvLen, sizeof(unsigned char));
	memcpy(pKeyIv, pRecKeyIv, nKeyIvLen);	
#endif

	if( nKeyIvLen != (nKeyLen + nIvLen) )
	{
		ret = m_tkscstk_err_code = TK_CSTK_ERROR_KEY_IV_LENGTH_MISSMATCH;
		goto err;
	}

	if(usKeyIv->value == NULL)
	{
		usKeyIv->length = nKeyIvLen;
		ret = m_tkscstk_err_code = TK_CSTK_SUCCESS;
		goto err;
	}

	memcpy(usKeyIv->value, pKeyIv, nKeyIvLen);
	usKeyIv->length = nKeyIvLen;

err:
	if(pKeyIv != NULL) { free(pKeyIv); pKeyIv=NULL; }
	if(pRecKeyIv != NULL) TrustKeystore_MemFree(&pRecKeyIv); 
	if(usDecKey.value != NULL) { free(usDecKey.value); memset(&usDecKey, 0x00, sizeof(UString)); }
	if(szKeyAlgo != NULL) TrustKeystore_MemFree(&szKeyAlgo);
	if(szKeyOPMode != NULL) TrustKeystore_MemFree(&szKeyOPMode);

	return ret;
}

/* ERROR */
/*	
	Name : TrustKeystoreTK_GetErrorCode
	Description: TrustKeystore CSTK 에러코드 반환 함수
	Parameters
	Return Value : 성공일 경우 0, 실패일 경우 에러코드 값
	Note : 
*/
//TKSCSTK_API int TrustKeystoreTK_GetErrorCode(void)
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_GetErrorCode(void)
#else
int TrustKeystoreTK_GetErrorCode(void)
#endif
{
	return m_tkscstk_err_code;
}
