/***********************************************
	 Copyright (C) 2015, UNETsystem
 
     test.c

	 Creadted by DEV3

************************************************/

#include <stdio.h>
#include <stdlib.h>
#ifdef _MSC_VER
#include <windows.h>
#endif
#ifdef WIN32
#include "../src/TrustKeystoreCstk.h"
#else
#include "../TrustKeystoreCstk.h"	
#endif

#ifdef WIN32
#pragma comment(lib, "TKSCstk.lib")
#endif

int TKSCstk_init(void **ppCtx, char* szPath);
int TKSCstk_hash(void *pCtx, int nAlgo, unsigned char* pMsg, int nMsgLen, unsigned char* pHash, int nHashLen);
int TKSCstk_block(void *pCtx);
int TKSCstk_hmac(void *pCtx);
int TKSCstk_ReqKey(void *pCtx, unsigned char  *pOut, int *nOutLen);
int TKSCstk_ResKey(void *pCtx, unsigned char  *pIn, int nInLen, unsigned char  *pOut, int *nOutLen);
int TKSCstk_SetKey(void *pCtx, unsigned char  *pIn, int nInLen);
int TKSCstk_GetKey(void *pCtx);
void TKSCstk_final(void **ppCtx);

typedef struct {
	char *szKeyID;
} BLK_ENC_KEY_ID;

BLK_ENC_KEY_ID blk_enc_keyid[] =
{
	{"SEED-256_OFB" },
	{"SEED-256_ECB" },
	{"SEED-256_CTR" },
	{"SEED-256_CFB" },
	{"SEED-256_CBC" },
	{"SEED-128_OFB" },
	{"SEED-128_ECB" },
	{"SEED-128_CTR" },
	{"SEED-128_CFB" },
	{"SEED-128_CBC" },
	{"LEA-256_OFB"	},
	{"LEA-256_ECB"	},
	{"LEA-256_CTR"	},
	{"LEA-256_CFB"	},
	{"LEA-256_CBC"	},
	{"LEA-192_OFB"	},
	{"LEA-192_ECB"	},
	{"LEA-192_CTR"	},
	{"LEA-192_CFB"	},
	{"LEA-192_CBC"	},
	{"LEA-128_OFB"	},
	{"LEA-128_ECB"	},
	{"LEA-128_CTR"	},
	{"LEA-128_CFB"	},
	{"LEA-128_CBC"	},
	{"ARIA-256_OFB" },
	{"ARIA-256_ECB" },
	{"ARIA-256_CTR" },
	{"ARIA-256_CFB" },
	{"ARIA-256_CBC" },
	{"ARIA-192_OFB" },
	{"ARIA-192_ECB" },
	{"ARIA-192_CTR" },
	{"ARIA-192_CFB" },
	{"ARIA-192_CBC" },
	{"ARIA-128_OFB" },
	{"ARIA-128_ECB" },
	{"ARIA-128_CTR" },
	{"ARIA-128_CFB" },
	{"ARIA-128_CBC" },
	{"AES-256_OFB"	},
	{"AES-256_ECB"	},
	{"AES-256_CTR"	},
	{"AES-256_CFB"	},
	{"AES-256_CBC"	},
	{"AES-192_OFB"	},
	{"AES-192_ECB"	},
	{"AES-192_CTR"	},
	{"AES-192_CFB"	},
	{"AES-192_CBC"	},
	{"AES-128_OFB"	},
	{"AES-128_ECB"	},
	{"AES-128_CTR"	},
	{"AES-128_CFB"	},
	{"AES-128_CBC"	},
	{""				}
};

typedef struct {
	char *szKeyID;
} HMAC_KEY_ID;

HMAC_KEY_ID hmac_keyid[] =
{
	{"HMAC-SHA512"	},
	{"HMAC-SHA256"  },
	{""				}
};

unsigned  char m_protocol[1024];
int m_protocol_len;

void main()
{
	void *pCtx=NULL;
	char *szConfPath = NULL; // Device Mode need not conf path
	unsigned char TobeHashData[2] = {0x00, 0x01};
	unsigned char HashedData[32] = {0x70,0x59,0x9e,0x67,0x39,0x9e,0xa1,0x45,0x8c,0x9d,0xdc,0xb8,0x31,0x4b,0x7a,0xbb,0x4c,0x6e,0x97,0xa5,0x97,0x98,0x4d,0x67,0x76,0xa3,0x0f,0xf5,0xbc,0x87,0xfe,0xd6};
	unsigned char ReqKeyMsg[1024] = {0,};
	unsigned char ResKeyMsg[1024] = {0,};
	int ret=0, nReqKeyMsgLen=0, nResKeyMsgLen=0;
	int nHashAlgo = TKS_CSTK_DIGEST_LSH256;

	ret = TKSCstk_hash(pCtx, nHashAlgo, TobeHashData, sizeof(TobeHashData), HashedData, sizeof(HashedData));
	if(ret)
	{
		goto err;
	}

before_init:
	ret = TKSCstk_init(&pCtx, szConfPath);
	if(ret)
	{
		goto err;
	}

	ret = TKSCstk_block(pCtx);
	if(ret)
	{
		if(ret == -5601) 
			goto reqkey;
		else if(ret == -4000)
			goto before_init;
		else
			goto err;
	}

	ret = TKSCstk_hmac(pCtx);
	if(ret)
	{
		goto err;
	}

reqkey:
	//ret = TKSCstk_ReqKey(pCtx, ReqKeyMsg, &nReqKeyMsgLen);
	ret = TKSCstk_ReqKey(pCtx, m_protocol, &m_protocol_len);
	if(ret)
	{
		goto err;
	}

	// Device Mode에서는 지원하지 않는 API
	/*
	ret = TKSCstk_ResKey(pCtx, ReqKeyMsg, nReqKeyMsgLen, ResKeyMsg, &nResKeyMsgLen);
	if(ret)
	{
		goto err;
	}
	*/

	ret = TKSCstk_SetKey(pCtx, ResKeyMsg, nResKeyMsgLen);
	if(ret)
	{
		goto err;
	}

	ret = TKSCstk_GetKey(pCtx);
	if(ret)
	{ 
		goto err;
	}

err:
	TKSCstk_final(&pCtx);
}


int TKSCstk_GetKey(void *pCtx)
{
	int ret=-1;
	int i=0, j=0;
	UString usKEYIV;
	char szKeyID[256] = {0,};

	memset(&usKEYIV, 0x00, sizeof(UString));

	printf("\nTest for TrustKeystoreTK_GetKey...start\n");

	printf("\nPlease Type Key ID...\n");
	if (scanf("%s", szKeyID)) 
	{
		printf("Key ID : [%s]\n", szKeyID);
    }

	usKEYIV.value = NULL;
	ret = TrustKeystoreTK_GetKey(pCtx, szKeyID, &usKEYIV);
	if(ret)
	{
		printf("TrustKeystoreTK_GetKey...failed : [%d]\n", TrustKeystoreTK_GetErrorCode());
		goto err;
	}

	usKEYIV.value = (unsigned char*)calloc(usKEYIV.length, sizeof(unsigned char));
	if(!usKEYIV.value)
	{
		printf("usKEYIV.value memory allocation...failed\n");
		goto err;
	}

	ret = TrustKeystoreTK_GetKey(pCtx, szKeyID, &usKEYIV);
	if(!ret)
	{
		printf("Request Key&IV length : [%d]\n", usKEYIV.length);
		printf("Request Key&IV : ");
		for(j=0; j<usKEYIV.length; j++)
			printf("%02X", usKEYIV.value[j]);
		printf("\n");
		printf("TrustKeystoreTK_GetKey...success : [%d]\n", TrustKeystoreTK_GetErrorCode());

	}else
	{
		printf("TrustKeystoreTK_GetKey...failed : [%d]\n", TrustKeystoreTK_GetErrorCode());
		goto err;
	}

err:
	if(usKEYIV.value != NULL)	{ free(usKEYIV.value); memset(&usKEYIV, 0x00, sizeof(UString)); }
	return ret;

}

int TKSCstk_init(void **ppCtx, char* szPath)
{
	int ret;

	printf("\nTest for TrustKeystoreTK_Init...start\n");

	ret = TrustKeystoreTK_Init(ppCtx, szPath);
	if(ret)
	{
		printf("trustKeystoreAgent.conf path : [%s]\n", szPath);
		printf("TrustKeystoreTK_Init...failed : [%d]\n", TrustKeystoreTK_GetErrorCode());
	}else
	{
		printf("trustKeystoreAgent.conf path : [%s]\n", szPath);
		printf("TrustKeystoreTK_Init...success : [%d]\n", TrustKeystoreTK_GetErrorCode());
	}

	return TrustKeystoreTK_GetErrorCode();
} 

void TKSCstk_final(void **ppCtx)
{
	printf("\nTest for TrustKeystoreTK_Final...start\n");
	if(*ppCtx != NULL) TrustKeystoreTK_Final(ppCtx);
} 

int TKSCstk_SetKey(void *pCtx, unsigned char  *pIn, int nInLen)
{
	int ret, i;
	UString usResMsg;

	memset(&usResMsg, 0x00, sizeof(UString));

	printf("\nTest for TrustKeystoreTK_SetKey...start\n");

	usResMsg.length = nInLen;
	usResMsg.value = pIn;

	printf("Response KeyMsg Length : [%d]\n", usResMsg.length);
	printf("Response KeyMsg : [");
	for(i=0; i<usResMsg.length;i++)
		printf("%02X", usResMsg.value[i]);
	printf("]\n");

	ret = TrustKeystoreTK_SetKey(pCtx, &usResMsg);
	if(!ret)
	{
		printf("TrustKeystoreTK_SetKey...success : [%d]\n", TrustKeystoreTK_GetErrorCode());
	}else
	{
		printf("TrustKeystoreTK_SetKey...failed : [%d]\n", TrustKeystoreTK_GetErrorCode());
	}

	return ret;
}

int TKSCstk_ResKey(void *pCtx, unsigned char  *pIn, int nInLen, unsigned char  *pOut, int *nOutLen)
{
	int ret=-1;
	int i=0, j=0;
	UString usIN, usEnc, usDec, usRegMsg, usResMsg;
	char *szKeyID = "SEED-128_CBC";
	char *szGWID = "test_device1";
	char *szIoTID = "test_device2";
	char *szPlain = "test_msg한글123!@#";
	char szResponderID[256] = {0,};

	memset(&usIN, 0x00, sizeof(UString));
	memset(&usEnc, 0x00, sizeof(UString));
	memset(&usDec, 0x00, sizeof(UString));
	memset(&usRegMsg, 0x00, sizeof(UString));
	memset(&usResMsg, 0x00, sizeof(UString));

	printf("\nTest for TrustKeystoreTK_MakeResponseKeyMsg...start\n");

	usRegMsg.length = nInLen;
	usRegMsg.value = pIn;

	printf("Request KeyMsg Length : [%d]\n", usRegMsg.length);
	printf("Request KeyMsg : [");
	for(i=0; i<usRegMsg.length;i++)
		printf("%02X", usRegMsg.value[i]);
	printf("]\n");

	printf("\nPlease Type Key Responder ID...\n");
	if (scanf("%s", szResponderID)) 
	{
		printf("Key Responder ID : [%s]\n", szResponderID);
    }

	usResMsg.value = NULL;
	ret = TrustKeystoreTK_MakeResponseKeyMsg(pCtx, szResponderID, &usRegMsg, &usResMsg);
	if(ret)
	{
		printf("TrustKeystoreTK_MakeResponseKeyMsg...failed : [%d]\n", TrustKeystoreTK_GetErrorCode());
		goto err;
	}

	usResMsg.value = (unsigned char*)calloc(usResMsg.length, sizeof(unsigned char));
	if(!usResMsg.value)
	{
		printf("usResMsg.value memory allocation...failed\n");
		goto err;
	}

	ret = TrustKeystoreTK_MakeResponseKeyMsg(pCtx, szResponderID, &usRegMsg, &usResMsg);
	if(!ret)
	{
		printf("Response Key Msg length : [%d]\n", usResMsg.length);
		printf("Response Key Msg : ");
		for(j=0; j<usResMsg.length; j++)
			printf("%02X", usResMsg.value[j]);
		printf("\n");
		printf("TrustKeystoreTK_MakeResponseKeyMsg...success : [%d]\n", TrustKeystoreTK_GetErrorCode());

		memcpy(pOut, usRegMsg.value, usRegMsg.length);
		*nOutLen = usRegMsg.length;
	}else
	{
		printf("TrustKeystoreTK_MakeResponseKeyMsg...failed : [%d]\n", TrustKeystoreTK_GetErrorCode());
		goto err;
	}

err:
	if(usResMsg.value != NULL)	{ free(usResMsg.value); memset(&usResMsg, 0x00, sizeof(UString)); }
	return ret;
}

int TKSCstk_ReqKey(void *pCtx, unsigned char  *pOut, int *nOutLen)
{
	int ret=-1;
	int i=0, j=0;
	UString usRegMsg, usResMsg;
	char szInputKeyID[256] = {0,};
	char szRequesterID[256] = {0,};

	memset(&usRegMsg, 0x00, sizeof(UString));
	memset(&usResMsg, 0x00, sizeof(UString));

	printf("\nTest for TrustKeystoreTK_MakeRequestKeyMsg...start\n");

	printf("\nPlease Type Request Key's KeyID...\n");
	if (scanf("%s", szInputKeyID)) 
	{
		printf("Request KeyID : [%s]\n", szInputKeyID);
    }

	printf("\nPlease Type Key Requester ID...\n");
	if (scanf("%s", szRequesterID)) 
	{
		printf("Key Requester ID : [%s]\n", szRequesterID);
    }

	usRegMsg.value = NULL;
	ret = TrustKeystoreTK_MakeRequestKeyMsg(pCtx, szRequesterID, szInputKeyID, &usRegMsg);
	if(ret)
	{
		printf("TrustKeystoreTK_MakeRequestKeyMsg...failed : [%d]\n", TrustKeystoreTK_GetErrorCode());
		goto err;
	}

	usRegMsg.value = (unsigned char*)calloc(usRegMsg.length, sizeof(unsigned char));
	if(!usRegMsg.value)
	{
		printf("usRegMsg.value memory allocation...failed\n");
		goto err;
	}

	ret = TrustKeystoreTK_MakeRequestKeyMsg(pCtx, szRequesterID, szInputKeyID, &usRegMsg);
	if(!ret)
	{
		printf("Request Key Msg length : [%d]\n", usRegMsg.length);
		printf("Request Key Msg : ");
		for(j=0; j<usRegMsg.length; j++)
			printf("%02X", usRegMsg.value[j]);
		printf("\n");
		printf("TrustKeystoreTK_MakeRequestKeyMsg...success : [%d]\n", TrustKeystoreTK_GetErrorCode());

		memcpy(pOut, usRegMsg.value, usRegMsg.length);
		*nOutLen = usRegMsg.length;
	}else
	{
		printf("TrustKeystoreTK_MakeRequestKeyMsg...failed : [%d]\n", TrustKeystoreTK_GetErrorCode());
		goto err;
	}

err:
	if(usRegMsg.value != NULL)	{ free(usRegMsg.value); memset(&usRegMsg, 0x00, sizeof(UString)); }
	return ret;
}

int TKSCstk_hmac(void *pCtx)
{
	int ret=-1;
	int i=0, j=0;
	UString usIN, usOut;
	char *szPlain = "test_msg한글123!@#";
	char szInputKeyID[256] = {0,};

	memset(&usIN, 0x00, sizeof(UString));
	memset(&usOut, 0x00, sizeof(UString));

	printf("\nTest for TrustKeystoreTK_GenerateHMAC...start\n");

	usIN.value = szPlain;
	usIN.length = strlen(szPlain);

	printf("\nPlease Type KeyID...\n");
	if (scanf("%s", szInputKeyID)) 
	{
		printf("InPut KeyID : [%s]\n", szInputKeyID);
    }

	printf("plain data length : [%d]\n", usIN.length);
	printf("plain data value : [%s]\n", usIN.value);

	usOut.value = NULL;
	ret = TrustKeystoreTK_GenerateHMAC(pCtx, szInputKeyID, &usIN, &usOut);
	if(ret)
	{
		printf("TrustKeystoreTK_GenerateHMAC...failed : [%d]\n", TrustKeystoreTK_GetErrorCode());
		goto err;
	}

	usOut.value = (unsigned char*)calloc(usOut.length, sizeof(unsigned char));
	if(!usOut.value)
	{
		printf("usOut.value memory allocation...failed \n");
		goto err;
	}

	ret = TrustKeystoreTK_GenerateHMAC(pCtx, szInputKeyID, &usIN, &usOut);
	if(!ret)
	{
		printf("hmac data length : [%d]\n", usOut.length);
		printf("hmac data value : ");
		for(j=0; j<usOut.length; j++)
			printf("%02X", usOut.value[j]);
		printf("\n");
		printf("TrustKeystoreTK_GenerateHMAC...success : [%d]\n", TrustKeystoreTK_GetErrorCode());
	}else
	{
		printf("TrustKeystoreTK_GenerateHMAC...failed : [%d]\n", TrustKeystoreTK_GetErrorCode());
	}

err:
	if(usOut.value != NULL)	{ free(usOut.value); memset(&usOut, 0x00, sizeof(UString)); }
	return ret;
}

int TKSCstk_block(void *pCtx)
{
	int ret=-1;
	int i=0, j=0;
	UString usIN, usEnc, usDec;
	char *szPlain = "test_msg한글123!@#";
	char szInputKeyID[256] = {0,};

	memset(&usIN, 0x00, sizeof(UString));
	memset(&usEnc, 0x00, sizeof(UString));
	memset(&usDec, 0x00, sizeof(UString));

	printf("\nTest for TrustKeystoreTK_Encipher & TrustKeystoreTK_Decrypt...start\n");

	usIN.value = szPlain;
	usIN.length = strlen(szPlain);

	printf("\nPlease Type KeyID...\n");
	if (scanf("%s", szInputKeyID)) 
	{
		printf("InPut KeyID : [%s]\n", szInputKeyID);
    }
	printf("plain data length : [%d]\n", usIN.length);
	printf("plain data value : [%s]\n", usIN.value);

	usEnc.value = NULL;
	ret = TrustKeystoreTK_Encipher(pCtx, szInputKeyID, &usIN, &usEnc);
	if(ret)
	{
		printf("TrustKeystoreTK_Encipher...failed : [%d]\n", TrustKeystoreTK_GetErrorCode());
		goto err;
	}

	usEnc.value = (unsigned char*)calloc(usEnc.length, sizeof(unsigned char));
	if(!usEnc.value)
	{
		printf("usEnc.value memory allocation...failed\n");
		goto err;
	}

	ret = TrustKeystoreTK_Encipher(pCtx, szInputKeyID, &usIN, &usEnc);
	if(!ret)
	{
		printf("enc data length : [%d]\n", usEnc.length);
		printf("enc data value : ");
		for(j=0; j<usEnc.length; j++)
			printf("%02X", usEnc.value[j]);
		printf("\n");
		printf("TrustKeystoreTK_Encipher...success : [%d]\n", TrustKeystoreTK_GetErrorCode());
	}else
	{
		printf("TrustKeystoreTK_Encipher...failed : [%d]\n", TrustKeystoreTK_GetErrorCode());
		goto err;
	}

	usDec.value = NULL;
	ret = TrustKeystoreTK_Decrypt(pCtx, szInputKeyID, &usEnc, &usDec);
	if(ret)
	{
		printf("TrustKeystoreTK_Decrypt...failed : [%d]\n", TrustKeystoreTK_GetErrorCode());
		goto err;
	}

	usDec.value = (unsigned char*)calloc(usDec.length, sizeof(unsigned char));
	if(!usDec.value)
	{
		printf("usDec.value memory allocation...failed\n");
		goto err;
	}

	ret = TrustKeystoreTK_Decrypt(pCtx, szInputKeyID, &usEnc, &usDec);
	if(!ret)
	{
		printf("dec data length : [%d]\n", usDec.length);
		printf("dec data value : [%s]\n", usDec.value);
		printf("TrustKeystoreTK_Decrypt...success : [%d]\n", TrustKeystoreTK_GetErrorCode());
	}else
	{
		printf("TrustKeystoreTK_Decrypt...failed : [%d]\n", TrustKeystoreTK_GetErrorCode());
	}

err:
	if(usEnc.value != NULL)	{ free(usEnc.value); memset(&usEnc, 0x00, sizeof(UString)); }
	if(usDec.value != NULL)	{ free(usDec.value); memset(&usDec, 0x00, sizeof(UString)); }

	return ret;
}

int TKSCstk_hash(void *pCtx, int nAlgo, unsigned char* pMsg, int nMsgLen, unsigned char* pHash, int nHashLen)
{
	int ret=-1;
	int i=0, j=0;
	int alg_nid;
	UString usIN, usOut;

	printf("\nTest for TrustKeystoreTK_Hash...start\n");

	if(nAlgo != TKS_CSTK_UNDEFINED)
	{
		memset(&usIN, 0x00, sizeof(UString));
		memset(&usOut, 0x00, sizeof(UString));

		alg_nid = nAlgo;
		usIN.length = nMsgLen;
		usIN.value = pMsg;

		printf("alg_nid : [%d]\n", alg_nid);
		printf("plain data length : [%d]\n", usIN.length);
		printf("plain data value : ");
		for(j=0; j<usIN.length; j++)
			printf("%02X", usIN.value[j]);
		printf("\n");

		usOut.value = NULL;
		ret = TrustKeystoreTK_Hash(alg_nid, &usIN, &usOut);
		if(ret)
		{
			goto err;
		}

		usOut.value = (unsigned char*)calloc(usOut.length, sizeof(unsigned char));
		if(!usOut.value)
		{
			goto err;
		}

		ret = TrustKeystoreTK_Hash(alg_nid, &usIN, &usOut);
		if(!ret)
		{
			printf("hash data length : [%d]\n", usOut.length);
			printf("hash data value : ");
			for(j=0; j<usOut.length; j++)
				printf("%02X", usOut.value[j]);
			printf("\n");

			if(usOut.length != nHashLen)
			{
				printf("TrustKeystoreTK_Hash KAT Test Failed...\n");
				printf("KAT length : [%d]\n", nHashLen);
				goto err;
			}

			if(memcmp(usOut.value, pHash, nHashLen) != 0)
			{
				printf("TCL_Digest KAT Test Failed...\n");
				printf("KAT value : ");
				for(j=0; j<nHashLen; j++)
					printf("%02X", pHash[j]);
				printf("\n");
				goto err;
			}
			printf("TrustKeystoreTK_Hash...success : [%d]\n", TrustKeystoreTK_GetErrorCode());
		}

		if(usOut.value != NULL)	{ free(usOut.value); memset(&usOut, 0x00, sizeof(UString)); }
	}

err:
	if(usOut.value != NULL)	{ free(usOut.value); memset(&usOut, 0x00, sizeof(UString)); }
	return ret;
}

