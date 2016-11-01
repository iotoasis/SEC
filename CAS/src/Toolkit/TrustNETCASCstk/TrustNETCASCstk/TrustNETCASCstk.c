#include <stdio.h>

#ifdef WIN32
#pragma comment (lib, "TrustNETCASClient.lib")
#endif

#include "../include/TrustNETCASClient.h"
#include "TrustNETCASCstk.h"

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/coding.h>

#define FOURK_BUF 4096

void *pContext;

int TK_Init(char *szConfPath)
{
	return TrustNet_Init(&pContext, szConfPath);
}

int TK_IssueCert(char *szDevId)
{
	int nRet = 0;
	
	if((nRet = TrustNet_IssueDeviceCert(pContext, szDevId, CERT_ISSUE)) != 0)
	{
		printf("TrustNet_IssueDeviceCert Failed!");
		goto err;
	}

err:

	return nRet;
}

int sign(char *signSrc, char *szPemPriKey, char *szPass, char **szSign)
{
	int nRet = 0;
	byte derKeyBuff[FOURK_BUF] = {0};
	byte msgDigest[FOURK_BUF] = {0};
	byte sig[FOURK_BUF] = {0};
	byte signB64[FOURK_BUF] = {0};
	int nDerKeyLen = 0;	
	word32 idx = 0;
	word32 sigSz = 0;
	word32 signB64Len = 0;
	ecc_key key;
	RNG rng;	
	int verified = 0;	

	if((nRet = wc_Sha256Hash(signSrc, strlen((char *)signSrc), msgDigest)) != 0)
		goto err;

	if((nRet = wc_InitRng(&rng)) != 0)
		goto err;

	if((nRet = wc_ecc_init(&key)) != 0)
		goto err;

	if((nDerKeyLen = wolfSSL_KeyPemToDer(szPemPriKey, strlen(szPemPriKey), derKeyBuff, FOURK_BUF, szPass)) < 0)
	{
		nRet = nDerKeyLen;
		goto err;
	}

	if((nRet = wc_EccPrivateKeyDecode(derKeyBuff, &idx, &key, FOURK_BUF)) != 0)
		goto err;

	sigSz = sizeof(sig);

	if((nRet = wc_ecc_sign_hash(msgDigest, 32, sig, &sigSz, &rng, &key)) != 0)
		goto err;

	signB64Len = sizeof(signB64);

	if((nRet = Base64_Encode(sig, sigSz, signB64, &signB64Len)) != 0)
		goto err;

	if((*szSign = (char*)calloc(signB64Len + 1, 1)) == NULL)
	{
		nRet = -1;
		goto err;
	}

	memcpy(*szSign, signB64, signB64Len);

err:

	return nRet;
}

int TK_Sign(char *szDevId, char * szSignSrc, char **ppAuthKey)
{
	int nRet = 0;
	char *pPriKey = NULL;
	char *pPass = NULL;
	char *pSign = NULL;

	if((nRet = TrustNet_GetDevicePrikeyAndPass(pContext, szDevId, &pPriKey, &pPass)) != 0)
	{
		printf("TrustNet_GetDevicePrikeyAndPass Failed!");
		goto err;
	}

	if((nRet = sign(szSignSrc, pPriKey, pPass, &pSign)) != 0)
		goto err;

	if((nRet = TrustNet_GetAuthKeyFromMEF(pContext, szDevId, szSignSrc, pSign, ppAuthKey)) != 0)
	{
		printf("TrustNet_GetAuthKeyFromMEF Failed!");
		goto err;
	}

err:

	return nRet;
}

int TK_Final()
{
	return TrustNet_Final((void **)(&pContext));
}
