#include "CertManager.h"

int CM_RegDeviceGetDN(Client_CTX *pCtx, char *szDeviceID, char **szDN, char **szKeyAlgo, char **szKeyLength)
{
	int		nRet		= 0;
	char	szMsg[256]	= {0};
	char	*pszReceive = NULL;
	Parser_PARAM stParam;

	memset(&stParam, 0x00, sizeof(Parser_PARAM));	

	sprintf(szMsg, "DEVICEID=%s&CACLIENTID=%s&CACLIENTHINT=%s", szDeviceID, pCtx->pConfig->clientID, pCtx->pConfig->clientHint);

	if((nRet = CM_ReqToCAServer(pCtx, REQPAGE_REG_DEVICE_GET_DN, szMsg, &pszReceive)) != 0)
	{
		goto err;
	}

	if((nRet = ParseXml(pszReceive, &stParam)) != 0)
	{
		nRet = ER_PARSEXML;
		goto err;
	}

	if(stParam.nResult == 0)
	{
		if((*szDN = (char*)calloc(strlen(stParam.response.pDn) + 1, 1)) == NULL)
		{
			nRet = ER_MALLOC;
			goto err;
		}
		memcpy(*szDN, stParam.response.pDn, strlen(stParam.response.pDn));

		if((*szKeyAlgo = (char*)calloc(strlen(stParam.response.pKeyAlgo) + 1, 1)) == NULL)
		{
			nRet = ER_MALLOC;
			goto err;
		}
		memcpy(*szKeyAlgo, stParam.response.pKeyAlgo, strlen(stParam.response.pKeyAlgo));

		if((*szKeyLength = (char*)calloc(strlen(stParam.response.pKeyLength) + 1, 1)) == NULL)
		{
			nRet = ER_MALLOC;
			goto err;
		}
		memcpy(*szKeyLength, stParam.response.pKeyLength, strlen(stParam.response.pKeyLength));
	}
	else
	{
		printf("\nCAS server error : [%d]\n", stParam.nResult);
		nRet = ER_RESULT;
	}

err:

	if(pszReceive)
		free(pszReceive);

	FreeParam(&stParam);

	return (nRet == 0 ? nRet : (nRet += ER_REGDEVICEGETDN));
}

int CM_IssueCertSimple(Client_CTX *pCtx, char *szDeviceID, char *szDN, char *szKeyAlgo, char *szKeyLength, char *szPass, char **szCert, char **szPriKey)
{
	int nRet = 0;
	char *pszCSR = NULL;
	char *pszReceive = NULL;
	char szMsg[4096] = {0};	
	Parser_PARAM stParam;

	memset(&stParam, 0x00, sizeof(Parser_PARAM));

	if((nRet = makeCSR(szDN, szKeyAlgo, strtol(szKeyLength, NULL, 10), szPass, &pszCSR, szPriKey)) != 0)
	{
		nRet = ER_MAKECSR;
		goto err;
	}

	sprintf(szMsg, "USERTYPE=%s&ID=%s&CSR=%s&CACLIENTID=%s&CACLIENTHINT=%s", TYPE_DEVICE, szDeviceID, pszCSR, pCtx->pConfig->clientID, pCtx->pConfig->clientHint);	

	if((nRet = CM_ReqToCAServer(pCtx, REQPAGE_ISSUE_CERT_SIMPLE, szMsg, &pszReceive)) != 0)
	{
		goto err;
	}

	if((nRet = ParseXml(pszReceive, &stParam)) != 0)
	{
		nRet = ER_PARSEXML;
		goto err;
	}

	if(stParam.nResult == 0)
	{
		unsigned int i = 0;

		if((*szCert = (char*)calloc(strlen(stParam.response.pCert) + 1, 1)) == NULL)
		{
			nRet = ER_MALLOC;
			goto err;
		}

		for(i = 0; i < strlen(stParam.response.pCert); i++)
		{
			if(stParam.response.pCert[i] == '|')
			{
				(*szCert)[i] = '\n';
			}
			else
			{
				(*szCert)[i] = stParam.response.pCert[i];
			}
		}
	}
	else
	{
		printf("\nCAS server error : [%d]\n", stParam.nResult);
		nRet = ER_RESULT;
	}

err:

	if(pszCSR)
		free(pszCSR);

	if(pszReceive)
		free(pszReceive);

	FreeParam(&stParam);

	return (nRet == 0 ? nRet : (nRet += ER_ISSUECERTSIMPLE));
}

int CM_AuthByCert(Client_CTX *pCtx, char *szID, char *szSignValue, char *szSignCert, char **szAuthKey)
{
	int nRet = 0;
	char szMsg[4096] = {0};
	char *pszReceive = NULL;
	Parser_PARAM stParam;

	memset(&stParam, 0x00, sizeof(Parser_PARAM));

	sprintf(szMsg, "USERTYPE=%s&ID=%s&SIGNVALUE=%s&CERT=%s", TYPE_DEVICE, szID, szSignValue, szSignCert);	

	if((nRet = CM_ReqToCAServer(pCtx, REQPAGE_AUTH_BY_CERT, szMsg, &pszReceive)) != 0)
		goto err;

	if((nRet = ParseXml(pszReceive, &stParam)) != 0)
	{
		nRet = ER_PARSEXML;
		goto err;
	}

	if(stParam.nResult == 0)
	{
		if((*szAuthKey = (char*)calloc(strlen(stParam.response.pAuthKey) + 1, 1)) == NULL)
		{
			nRet = ER_MALLOC;
			goto err;
		}
		memcpy(*szAuthKey, stParam.response.pAuthKey, strlen(stParam.response.pAuthKey));
	}
	else
	{
		printf("\nCAS server error : [%d]\n", stParam.nResult);
		nRet = ER_RESULT;
	}

err:

	if(pszReceive)
		free(pszReceive);

	FreeParam(&stParam);

	return (nRet == 0 ? nRet : (nRet += ER_AUTHBYCERT));
}

int CM_ReqToCAServer(Client_CTX *pCtx, char *reqPage, char *szMsg, char **szResponse)
{
	int nRet = 0;
	int nReceiveLen = 0;
	char *pszRequest = NULL;	

	if((nRet = MakeRequest(pCtx->pConfig->casIP, pCtx->pConfig->casPort, reqPage, szMsg, &pszRequest)) != 0)
	{
		nRet = ER_REQTOCASERVER_MAKEREQUEST;
		goto err;
	}

	if((nRet = Connect(pCtx->sslCtx, pCtx->pConfig->casIP, (unsigned short)strtol(pCtx->pConfig->casPort, NULL, 10), 0)) != 0)
	{
		nRet = ER_REQTOCASERVER_CONNECT;
		goto err;
	}

	if((nRet = SEND(pszRequest, strlen(pszRequest))) != 0)
	{
		nRet = ER_REQTOCASERVER_SEND;
		goto err;
	}

	if((nRet = HTTP_RECV(szResponse, &nReceiveLen)) != 0)
	{
		nRet = ER_REQTOCASERVER_HTTP_RECV;
		goto err;
	}

err:

	Disconnect();

	if(pszRequest)
		free(pszRequest);

	return nRet;
}

int CM_MakeCertPass(char *szDeviceID, char **szPass)
{
	int nRet = 0;
	int i = 0;
	int nDeviceIDLen = 0;
	char *pHMACKey = NULL;	
	UString usHMACKey, usHMACIn, usHMACOut;

	memset(&usHMACKey, 0x00, sizeof(UString));
	memset(&usHMACIn, 0x00, sizeof(UString));
	memset(&usHMACOut, 0x00, sizeof(UString));

	// 	개인키 비번 : HMAC-SHA256(Device G/W ID)
	// 	생성 - key : Device G/W ID 역순	
	nDeviceIDLen = strlen(szDeviceID);

	if((pHMACKey = (char *)calloc(nDeviceIDLen + 1, 1)) == NULL)
	{
		nRet = ER_MALLOC;
		goto err;
	}

	for(i = 0; i < nDeviceIDLen; i++)
	{
		pHMACKey[i] = szDeviceID[nDeviceIDLen - 1 - i];
	}

	if((nRet = setUString(&usHMACKey, pHMACKey, strlen(pHMACKey))) != 0)
	{
		nRet = ER_SETUSTRING;
		goto err;
	}

	if((nRet = setUString(&usHMACIn, szDeviceID, nDeviceIDLen)) != 0)
	{
		nRet = ER_SETUSTRING;
		goto err;
	}

	if((nRet = makeHMAC(SHA256, &usHMACKey, &usHMACIn, &usHMACOut)) != 0)
	{
		nRet = ER_MAKEHMAC;
		goto err;
	}

	if((nRet = base64Encoding(&usHMACOut, szPass)) != 0)
	{
		nRet = ER_BASE64ENCODING;
		goto err;
	}

err:

	if(pHMACKey)
		free(pHMACKey);

	if(usHMACKey.value)
		free(usHMACKey.value);

	if(usHMACIn.value)
		free(usHMACIn.value);

	if(usHMACOut.value)
		free(usHMACOut.value);

	return (nRet == 0 ? nRet : (nRet += ER_MAKECERTPASS));
}

int CM_SaveCertSet(char *szDeviceID, char *szCert, char *szPriKey)
{
	int nRet = 0;
	char *pCertDir = NULL;
	char szFilePath[MAX_PATH] = {0};

	//	linux : user home
	//	windows : user home/appdata/localow
	// 	UNETsystem/TrustNETCAS/CertStorage/USER/deviceID폴더/signCert.der
	// 	UNETsystem/TrustNETCAS/CertStorage/USER/deviceID폴더/signPri.key

	pCertDir = CM_GetCertDir(szDeviceID);
	
	MakeDirRecursive(pCertDir);

	// 인증서 저장
	sprintf(szFilePath, "%s%s", pCertDir, "signCert.pem");

	if((nRet = WriteTxtFile(szFilePath, szCert)) != 0)
	{
		nRet = ER_WRITETXTFILE;
		goto err;
	}

	// 개인키 저장
	memset(szFilePath, 0x00, sizeof(szFilePath));

	sprintf(szFilePath, "%s%s", pCertDir, "signKey.pem");

	if((nRet = WriteTxtFile(szFilePath, szPriKey)) != 0)
	{
		nRet = ER_WRITETXTFILE;
		goto err;
	}

err:

	return (nRet == 0 ? nRet : (nRet += ER_SAVECERTSET));
}

int CM_GetCertSet(char *szDeviceID, char **szCert, char **szPriKey)
{
	int nRet = 0;
	char *pCertDir = NULL;
	char szFilePath[MAX_PATH] = {0};

	if(szCert == NULL && szPriKey == NULL)
	{
		nRet = ER_ARG;
		goto err;
	}

	pCertDir = CM_GetCertDir(szDeviceID);

	if(szCert != NULL)
	{
		sprintf(szFilePath, "%s%s", pCertDir, "signCert.pem");

		if((nRet = ReadTxtFile(szFilePath, szCert)) != 0)
		{
			nRet = ER_READTXTFILE;
			goto err;
		}
	}	

	memset(szFilePath, 0x00, sizeof(szFilePath));

	if(szPriKey != NULL)
	{
		sprintf(szFilePath, "%s%s", pCertDir, "signKey.pem");

		if((nRet = ReadTxtFile(szFilePath, szPriKey)) != 0)
		{
			nRet = ER_READTXTFILE;
			goto err;
		}
	}

err:

	return (nRet == 0 ? nRet : (nRet += ER_GETCERTSET));
}

char* CM_GetCertDir(char *szDeviceID)
{
	static char szRetDir[MAX_PATH] = {0};
#ifdef WIN32
	char szCertDir[] = "Appdata\\LocalLow\\UNETsystem\\TrustNETCAS\\CertStorage\\USER";
	sprintf(szRetDir, "%s\\%s\\%s\\", getenv( "USERPROFILE" ), szCertDir, szDeviceID);
#else
	char szCertDir[] = "/UNETsystem/TrustNETCAS/CertStorage/USER";
	sprintf(szRetDir, "%s/%s/%s/", getenv( "HOME" ), szCertDir, szDeviceID);
#endif

	return szRetDir;
}

int CM_VerifyCert(char *szDeviceID)
{
	int nRet = 0;
	char *pCert = NULL;


 	if((nRet = CM_GetCertSet(szDeviceID, &pCert, NULL)) != 0)
		goto err;

	if((nRet = verifyCert(pCert)) != 0)
		goto err;

err:
	
	return nRet;
}

int CM_InitContext(Client_CTX **ppCtx)
{
	int nRet = 0;

	if(ppCtx == NULL || *ppCtx != NULL)
	{
		nRet = ER_ARG;
		goto err;
	}

	if((*ppCtx = (Client_CTX *)calloc(1, sizeof(Client_CTX))) == NULL)
	{
		nRet = ER_MALLOC;
		goto err;
	}

	if(((*ppCtx)->pConfig = (Config *)calloc(1, sizeof(Config))) == NULL)
	{
		nRet = ER_MALLOC;
		goto err;
	}

err:

	return (nRet == 0 ? nRet : (nRet += ER_INITCONTEXT));
}

int CM_CheckContext(Client_CTX *pCtx)
{
	int nRet = 0;

	if(pCtx == NULL || pCtx->pConfig == NULL)
		nRet = ER_CHECKCONTEXT;

	return nRet;
}

int CM_CheckDeviceID(Client_CTX *pCtx, char *szDeviceID)
{
	int nRet = 0;

	// device ID와 client ID가 동일해야 한다.
	if( _stricmp(pCtx->pConfig->clientID, szDeviceID) != 0 )
		nRet = ER_CHECKDEVICEID;

	return nRet;
}

int CM_FinalContext(Client_CTX **pCtx)
{
	int nRet = 0;

	if(*pCtx == NULL || (*pCtx)->pConfig == NULL)
	{
		nRet = ER_ARG;
		goto err;
	}

	free((*pCtx)->pConfig);
	free(*pCtx);
	
err:

	return (nRet == 0 ? nRet : (nRet += ER_FINALCONTEXT));
}

int CM_SetConfig(Client_CTX *pCtx, char *szConfPath)
{
	int		nRet = 0;
	FILE	*pfile = NULL;
	char	szConfFileName[MAX_PATH] = {0};
	char	szBuff[MAX_PATH] = {0};		// file read 버퍼
	char	seperate[] = "= \t\n\r";
	char	*pToken = NULL;

	if(pCtx == NULL || pCtx->pConfig == NULL || szConfPath == NULL || strlen(szConfPath) < 1 ||
		strlen(szConfPath) >= sizeof(pCtx->pConfig->clientHomeDir) + strlen(CLIENT_CONF_FILE_NAME))
	{
		nRet = ER_ARG;
		goto error;
	}	

	strncpy(pCtx->pConfig->clientHomeDir, szConfPath, sizeof(pCtx->pConfig->clientHomeDir) -1);
	sprintf(szConfFileName, "%s/%s", pCtx->pConfig->clientHomeDir, CLIENT_CONF_FILE_NAME);

	if((pfile = fopen(szConfFileName, "r")) == NULL)
	{
		nRet = ER_FILEOPEN;
		goto error;
	}

	while(!feof(pfile))
	{
		if(fgets(szBuff, sizeof(szBuff), pfile) == NULL)
			break;

		if((pToken = strtok(szBuff, seperate)) == NULL)
			continue;

		if(strcmp(pToken, "casIP") == 0)
		{
			if((pToken = strtok(NULL, seperate)) == NULL)
				continue;
			strncpy(pCtx->pConfig->casIP, pToken, sizeof(pCtx->pConfig->casIP) -1);
		}
		else if(strcmp(pToken, "casPort") == 0)
		{			
			if((pToken = strtok(NULL, seperate)) == NULL)
				continue;

			strncpy(pCtx->pConfig->casPort, pToken, sizeof(pCtx->pConfig->casPort) -1);
		}
		else if(strcmp(pToken, "caClientID") == 0)
		{
			if((pToken = strtok(NULL, seperate)) == NULL)
				continue;

			strncpy(pCtx->pConfig->clientID, pToken, sizeof(pCtx->pConfig->clientID) -1);
		}
		else if(strcmp(pToken, "caClientHint") == 0)
		{
			// strtok로 파싱할 경우 base64encode 문자열의 패딩문자'='가 유실될 수 있으므로 사용하지 않는다.
			unsigned int i = 0;
			int nClientHintPtr = 0;
			int bStartStr = 0;		// base64encode 문자열의 '='를 살리기 위한 플래그

			pToken = pToken + strlen(pToken);

			while(1)
			{
				if(*pToken != '\0' && *pToken != ' ' && *pToken != '=' && *pToken != '\t' && *pToken != '\r' && *pToken != '\n')
					break;
				else
					pToken++;
			}

			for(i = 0; i < strlen(pToken); i++)
			{
				if(bStartStr == 0 && pToken[i] != ' ' && pToken[i] != '=' && pToken[i] != '\t' && pToken[i] != '\r' && pToken[i] != '\n')
				{
					pCtx->pConfig->clientHint[nClientHintPtr++] = pToken[i];
					bStartStr = 1;
				}
				else if(bStartStr == 1 && pToken[i] != ' ' && pToken[i] != '\t' && pToken[i] != '\r' && pToken[i] != '\n')
				{
					pCtx->pConfig->clientHint[nClientHintPtr++] = pToken[i];					
				}
			}
		}
	}

error:

	if(pfile)
		fclose(pfile);

	return (nRet == 0 ? nRet : (nRet += ER_SETCONFIG));
}

int CM_InitComm(Client_CTX *pCtx)
{
	int nRet = 0;

	if((nRet = COMM_INIT(&(pCtx->sslCtx), SSL_SERVER_CA_CERT_NAME, pCtx->pConfig->clientHomeDir)) != 0)
	{
		nRet = ER_INITCOMM;
	}

	return nRet;
}

void CM_FinalComm(Client_CTX *pCtx)
{
	COMM_FINAL(&(pCtx->sslCtx));
}

void CM_MemFree(void **ppMem)
{
	if(ppMem != NULL && *ppMem != NULL)
	{
		free(*ppMem);
		*ppMem = NULL;
	}
}
