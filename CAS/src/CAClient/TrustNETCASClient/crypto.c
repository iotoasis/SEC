#include "crypto.h"
#include <time.h>

#define FOURK_BUF 4096

int makeHMAC(int nAlgo, UString *pKey, UString *pInfo, UString *pOut)
{
	int nRet = 0;
	byte *pHMAC = NULL;
	int nHMACLen = 0;
	Hmac   hmac;	

	if(pKey->value == NULL || pKey->length == 0 || pInfo->value == NULL || pInfo->length == 0 || pOut == NULL)
	{
		nRet = -1;
		goto error;
	}

	switch(nAlgo)
	{
	case SHA256:
		nHMACLen = SHA256_DIGEST_SIZE;
		if((pHMAC = (byte*)calloc(nHMACLen, 1)) == NULL)
		{
			nRet = -1;
			goto error;
		}		
		break;
	default:
		nRet = -1;
		goto error;
		break;
	}

	if((nRet = wc_HmacSetKey(&hmac, nAlgo, (byte *)pKey->value, (word32)pKey->length)) != 0)
	{
		goto error;
	}

	if((nRet = wc_HmacUpdate(&hmac, (byte *)pInfo->value, (word32)pInfo->length)) != 0)
	{
		goto error;
	}

	if((nRet = wc_HmacFinal(&hmac, pHMAC)) != 0)
	{
		goto error;
	}
		
	if((nRet = setUString(pOut, (char*)pHMAC, nHMACLen)) != 0)
		goto error;

error:
	if(pHMAC)
		free(pHMAC);	

	return nRet;
}

int digestSha256(UString *pusIn, UString *pusOut)
{
	int nRet = 0;
	byte hash[32] = {0}; /*SHA_256_LEN*/

	if((nRet = wc_Sha256Hash((byte*)pusIn->value, (word32)pusIn->length, hash)) != 0)
	{
		goto error;
	}
	if((nRet = setUString(pusOut, (char*)hash, sizeof(hash))) != 0)
		goto error;

error:

	return nRet;
}

int base64Encoding(UString *f, char **t)
{
	int nRet = 0;
	int i = 0;
	unsigned long l = 0;
	int outlen = BASE64ENCODESIZE(f->length);
	unsigned char *address ;
	unsigned char * psrc = f->value;

	if((*t = (char *)calloc(outlen, 1)) == NULL)	
	{
		nRet = -1;
		goto error;
	}

	address = (unsigned char *)*t;

	for (i = f->length; i > 0; i -= 3)
	{
		if (i >= 3)
		{
			l=	(((unsigned long)psrc[0])<<16L)|
				(((unsigned long)psrc[1])<< 8L)|psrc[2];
			*((*t)++)=conv_bin2ascii(l>>18L);
			*((*t)++)=conv_bin2ascii(l>>12L);
			*((*t)++)=conv_bin2ascii(l>> 6L);
			*((*t)++)=conv_bin2ascii(l     );

			psrc += 3;
		}
		else
		{
			l=((unsigned long)psrc[0])<<16L;
			if (i == 2) l|=((unsigned long)psrc[1]<<8L);

			*((*t)++)=conv_bin2ascii(l>>18L);
			*((*t)++)=conv_bin2ascii(l>>12L);
			*((*t)++)=(i == 1)?'=':conv_bin2ascii(l>> 6L);
			*((*t)++)='=';
		}
	}

	**t= '\0' ;
	*t = (char *)address;

error:

	return nRet;
}

int makeCSR(char *szDN, char *szkeyAlgo, int keyLength, char * szPass, char **szCSR, char **szPemPriKey)
{
	int nRet = 0;
	Cert req;
	WOLFSSL_EC_KEY* wolf_ecc = NULL;
	ecc_key *pKey = NULL;
	RNG rng;
	word32 reqDerSz = 0, reqPemSz = 0, sigSz = 0, privatekeyderSz = 0, privatekeypemSz = 0;
	byte reqDer[FOURK_BUF] = {0};
	byte reqPem[FOURK_BUF] = {0};
	byte privatekeyder[FOURK_BUF] = {0};
	byte privatekeyPem[FOURK_BUF] = {0};
	int nPemPrikeyLen = 0;

	// 정부과제는 ecdsa만 지원
	if(_stricmp(szkeyAlgo, "ecdsa") != 0)
	{
		nRet = -1;
		goto err;
	}

	// 1.ecc keypair 생성	
	if(keyLength == 224)
	{
		wolf_ecc = wolfSSL_EC_KEY_new_by_curve_name(ECC_SECP224R1);
	}
	else if(keyLength == 256)
	{
		wolf_ecc = wolfSSL_EC_KEY_new_by_curve_name(ECC_SECP256R1);
	}
	else
	{
		nRet = -1;
		goto err;
	}

	if(wolfSSL_EC_KEY_generate_key(wolf_ecc) == SSL_FAILURE)
	{
		nRet = -1;
		goto err;
	}

	pKey = (ecc_key *)(wolf_ecc->internal);

	if((nRet = wc_InitRng(&rng)) != 0)
	{
		goto err;
	}

	// 2. CSR 생성
	wc_InitCert(&req);

	if((nRet = setSubject(&(req.subject), szDN)) != 0)
	{
		goto err;
	}

	req.sigType = CTC_SHA256wECDSA;

	if((reqDerSz = wc_MakeCertReq(&req, reqDer, FOURK_BUF, NULL, pKey)) < 0)
	{
		nRet = -1;
		goto err;
	}

	if((reqDerSz = wc_SignCert(req.bodySz, req.sigType, reqDer, FOURK_BUF, NULL, pKey, &rng)) < 0)
	{
		nRet = -1;
		goto err;
	}

	if((reqPemSz = wc_DerToPem(reqDer, reqDerSz, reqPem, FOURK_BUF, CERTREQ_TYPE)) <0 )
	{
		nRet = -1;
		goto err;
	}

	if((*szCSR = (char*)calloc(1, reqPemSz + 1)) == NULL)
	{
		nRet = -1;
		goto err;
	}
	strncpy(*szCSR, reqPem, reqPemSz + 1);

	// 3.개인키 생성	
	if(wolfSSL_PEM_write_mem_ECPrivateKey(wolf_ecc, wolfSSL_EVP_des_ede3_cbc(), szPass, strlen(szPass), szPemPriKey, &nPemPrikeyLen) == SSL_FAILURE)
	{
		nRet = -1;
		goto err;
	}
	
err:

	wolfSSL_EC_KEY_free(wolf_ecc);
	return nRet;
}

int verifyCert(char *szPemCert)
{
	int nRet = 0;
	int nExpireDay = 30;
	unsigned char derBuf[4096] = {0};
	int derSz = 0;
	DecodedCert *pCert;
	byte date[MAX_DATE_SIZE] = {0};
	byte timeFormat = 0;
	time_t ltime;
	struct tm  certTime, *localTime;
	int i = 0;
	int timeDiff = 0;
	int diffHH = 0;
	int diffMM = 0;
	int diffSign = 0;
	
	if((derSz = wolfSSL_CertPemToDer((const unsigned char*)szPemCert, strlen(szPemCert), derBuf, sizeof(derBuf), CERT_TYPE)) < 0)
	{
		nRet = -1;
		goto err;
	}

	if((pCert = (DecodedCert *)calloc(sizeof(DecodedCert), 1)) == NULL)
	{
		nRet = -1;
		goto err;
	}

	InitDecodedCert(pCert, (byte*)derBuf, derSz, NULL);

	if((nRet = ParseCert(pCert, CERT_TYPE, NO_VERIFY, NULL)) != 0)
		goto err;

	timeFormat = pCert->afterDate[0];
	memcpy(date, &(pCert->afterDate[2]), pCert->afterDateLen - 2); // 앞 두 바이트는 asn1time의 포맷과 길이값
		
	if (!ExtractDate(date, timeFormat, &certTime, &i))
	{
		nRet = -1;			
		goto err;
	}

	if ((date[i] == '+') || (date[i] == '-'))
	{
		//WOLFSSL_MSG("Using time differential, not Zulu") ;
		diffSign = date[i++] == '+' ? 1 : -1 ;
		//GetTime(&diffHH, date, &i);
		diffHH += (date[i++] - 0x30) * 10;
		diffHH += (date[i++] - 0x30);
		//GetTime(&diffMM, date, &i);
		diffMM += (date[i++] - 0x30) * 10;
		diffMM += (date[i++] - 0x30);		
		
		timeDiff = diffSign * (diffHH*60 + diffMM) * 60 ;
	}

	ltime = time(NULL);
	ltime -= (time_t)timeDiff ;
	ltime -= (time_t)(nExpireDay * 24 * 60 * 60);	//만료 30일전 갱신
	localTime = gmtime(&ltime);

	// 비교
	if(localTime->tm_year < certTime.tm_year)
	{
		nRet = 0;
	}
	else if(	localTime->tm_year	==	certTime.tm_year &&
				localTime->tm_mon	<	certTime.tm_mon		)
	{
		nRet = 0;
	}
	else if(	localTime->tm_year	==	certTime.tm_year &&
				localTime->tm_mon	==	certTime.tm_mon &&
				localTime->tm_mday	<	certTime.tm_mday	)
	{
		nRet = 0;
	}
	else if(	localTime->tm_year	==	certTime.tm_year	&&
				localTime->tm_mon	==	certTime.tm_mon		&&
				localTime->tm_mday	==	certTime.tm_mday	&&
				localTime->tm_hour	<	certTime.tm_hour		)
	{
		nRet = 0;
	}
	else if(	localTime->tm_year	==	certTime.tm_year	&&
				localTime->tm_mon	==	certTime.tm_mon		&&
				localTime->tm_mday	==	certTime.tm_mday	&&
				localTime->tm_hour	==	certTime.tm_hour	&&
				localTime->tm_min	<	certTime.tm_min			)
	{
		nRet = 0;
	}
	else if(	localTime->tm_year	==	certTime.tm_year	&&
				localTime->tm_mon	==	certTime.tm_mon		&&
				localTime->tm_mday	==	certTime.tm_mday	&&
				localTime->tm_hour	==	certTime.tm_hour	&&
				localTime->tm_min	==	certTime.tm_min		&&
				localTime->tm_sec	<	certTime.tm_sec			)
	{
		nRet = 0;
	}
	else
	{
		nRet = -1;
	}

err:

	FreeDecodedCert(pCert);

	return nRet;
}

int setSubject(CertName *subject, char *szDN)
{
	int nRet = 0;
	int nIdx = 0;
	char szToken[] = ",";	
	char *pToken = NULL;
	char *pszTempDN = NULL;

	pszTempDN = (char*)calloc(strlen(szDN) + 1, sizeof(char));
	strncpy(pszTempDN, szDN, strlen(szDN) + 1);

	pToken = strtok(pszTempDN, szToken);
	
	while(pToken)
	{
		char *posEqual = NULL;
		char szItem[CTC_NAME_SIZE + 1] = {0};
		char *pName = NULL;

		if((posEqual = strstr(pToken, "=")) == NULL)
		{
			nRet = -1;
			goto err;
		}

		strncpy(szItem, pToken, posEqual - pToken);

		if(_stricmp(szItem, "cn") == 0)
		{
			pName = subject->commonName;
		}
		else if(_stricmp(szItem, "ou") == 0)
		{
			pName = subject->unit;
		}
		else if(_stricmp(szItem, "o") == 0)
		{
			pName = subject->org;
		}
		else if(_stricmp(szItem, "c") == 0)
		{
			pName = subject->country;
		}

		strncpy(pName, posEqual+1, CTC_NAME_SIZE);

		pToken = strtok(NULL, szToken);
	}

err:
	
	free(pszTempDN);

	return nRet;
}

int setUString(UString *pUS, char* value, int length)
{
	int nRet = 0;

	if(pUS == NULL || length == 0)
	{
		nRet = -1;
		goto error;
	}

	if((pUS->value = (unsigned char*)calloc(length + 1, 1)) == NULL)	// +1 for string
	{
		nRet = -1;
		goto error;
	}
	pUS->length = length;

	if(value != NULL)
		memcpy(pUS->value, value, length);	

error:
	return nRet;	
}

void freeUString(UString *pUS)
{
	if(pUS != NULL)
	{
		free(pUS->value);
		memset(pUS, 0x00, sizeof(UString));
	}
}
