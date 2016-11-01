#include "crypto.h"

int TK_Aes128_Encrypt(UString *pOut, UString *pIn, UString *pKeyIV)
{
#ifndef NO_WOLF_CRYPT
	int nRet = 0;
	int nOutLen = 0;
	int i = 0;
	Aes  aes;

	/* 패딩을 붙였을 경우 ciphertext길이 계산 */
	pOut->length = (pIn->length + AES_BLOCK_SIZE ) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
	if((pOut->value = (unsigned char*) TK_MemAlloc(pOut->length)) == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
		goto error;
	}
	memcpy(pOut->value, pIn->value, pIn->length);

	/* 패딩을 붙인다. */
	for(i = pIn->length; i<pOut->length; i++)
	{
		pOut->value[i] = pOut->length - pIn->length;
	}

	if((nRet = wc_AesSetKey(&aes, pKeyIV->value, AES_128_KEY_SIZE, pKeyIV->value + AES_128_KEY_SIZE, AES_ENCRYPTION)) != 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_AES128_ENCRYPT_WC_SETKEY;
		goto error;
	}
	if((nRet = wc_AesCbcEncrypt(&aes, pOut->value, pOut->value, pOut->length)) != 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_AES128_ENCRYPT_WC_AES_CBCENCRYPT;
		goto error;
	}

error:

	return nRet;
#else
	int nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_AES128_ENCRYPT;

	return nRet;
#endif
}

int TK_Aes128_Decrypt(UString *pOut, UString *pIn, UString *pKeyIV)
{
#ifndef NO_WOLF_CRYPT
	int nRet = 0;
	int nPaddingNumber = 0;
	int i = 0;
	int npInEnd = pIn->length -1;

	if((pOut->value = (unsigned char *) TK_MemAlloc(pIn->length)) == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
		goto error;
	}

	if((nRet = wc_AesCbcDecryptWithKey(pOut->value, pIn->value, pIn->length, pKeyIV->value, AES_128_KEY_SIZE, pKeyIV->value + AES_128_KEY_SIZE)) != 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_AES128_DECRYPT_WC_AES_CBCDECRYPT;
		goto error;
	}
	// 패딩 제거
	nPaddingNumber = pOut->value[npInEnd];

	for(i = npInEnd; i > npInEnd - nPaddingNumber; i--)
	{
		if(pOut->value[i] != nPaddingNumber)
		{
			// padding error!
			nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_AES128_DECRYPT_PADDINGERROR;
			goto error;
		}
	}

	pOut->length = pIn->length - nPaddingNumber;

error:

	return nRet;
#else
	int nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_AES128_DECRYPT;

	return nRet;
#endif
}

int TK_Make_Random(char* rand, int nLen)
{
#ifndef NO_WOLF_CRYPT
	int nRet = 0;
	RNG rng;

	if(rand == NULL || nLen == 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MAKE_RANDOM_ARG_ERROR;
		goto error;
	}
	if((nRet = wc_InitRng(&rng)) != 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MAKE_RANDOM_WC_INIT_RNG;
		goto error;
	}
	if((nRet = wc_RNG_GenerateBlock(&rng, (byte*)rand, (word32)nLen)) != 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MAKE_RANDOM_WC_RNG_GENBLOCK;
		goto error;
	}
	if((nRet = wc_FreeRng(&rng)) != 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MAKE_RANDOM_WC_FREE_RNG;
		goto error;
	}

error:

	return nRet;
#else
	int nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MAKE_RANDOM;

	return nRet;
#endif
}

int TK_Make_HMAC(int nAlgo, UString *pKey, UString *pInfo, UString *pOut)
{
#ifndef NO_WOLF_CRYPT
	int nRet = 0;
	byte *pHMAC = NULL;
	int nHMACLen = 0;
	Hmac   hmac;

	PRINT_DEBUG("TK_Make_HMAC Start.");

	if(pKey->value == NULL || pKey->length == 0 || pInfo->value == NULL || pInfo->length == 0 || pOut == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MAKE_HMAC_ARG_ERROR;
		goto error;
	}

	switch(nAlgo)
	{
	case SHA256:
		nHMACLen = SHA256_DIGEST_SIZE;
		if((pHMAC = (byte*)TK_MemAlloc(nHMACLen)) == NULL)
		{
			nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
			goto error;
		}		
		break;
	default:
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MAKE_HMAC_INVALID_ALGO;
		goto error;
		break;
	}

	if((nRet = wc_HmacSetKey(&hmac, nAlgo, (byte *)pKey->value, (word32)pKey->length)) != 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MAKE_HMAC_WC_HMAC_SETKEY;
		goto error;
	}
	if((nRet = wc_HmacUpdate(&hmac, (byte *)pInfo->value, (word32)pInfo->length)) != 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MAKE_HMAC_WC_HMAC_UPDATE;
		goto error;
	}
	if((nRet = wc_HmacFinal(&hmac, pHMAC)) != 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MAKE_HMAC_WC_HMAC_FINAL;
		goto error;
	}
	if((nRet = TK_Set_UString(pOut, (char*)pHMAC, nHMACLen)) != TK_SUCCESS)
		goto error;

	PRINT_DEBUG("TK_Make_HMAC Success.\n");

error:
	TK_MemFree((void**)&pHMAC);	

	return nRet;
#else
	int nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MAKE_HMAC;

	return nRet;
#endif

}

int TK_Sha256Hash(UString *pusIn, UString *pusOut)
{
	int nRet = 0;
	byte hash[SHA_256_LEN] = {0};

#ifndef NO_WOLF_CRYPT
	if((nRet = wc_Sha256Hash((byte*)pusIn->value, (word32)pusIn->length, hash)) != 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_SHA256HASH_WC_SHA256;
		goto error;
	}
	if((nRet = TK_Set_UString(pusOut, (char*)hash, SHA_256_LEN)) != TK_SUCCESS)
		goto error;
#else
	nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_SHA256HASH;
#endif
error:

	return nRet;
}
