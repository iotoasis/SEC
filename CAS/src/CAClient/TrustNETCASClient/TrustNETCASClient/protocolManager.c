#include "protocolManager.h"

int MakeRequest(char *szReqIP, char *szReqPort, char *szReqPage, char* szMsg, char** szRequest)
{
	int nRet = 0;
	char http_header[256] = "";
	char method[] = "POST";
	char szNewLine[] = "\r\n";
	int nContentLength = 0;
	char *szUriEncoded = NULL;

 	if((nRet = UriEncodeValue(szMsg, &szUriEncoded)) != 0)
 		goto err;

	nContentLength = strlen(szUriEncoded) + strlen(szNewLine);


	// make http header
	sprintf(http_header, "%s %s HTTP/1.1%sHost: %s:%s%sContent-Length: %d%s%s", method, szReqPage, szNewLine, szReqIP, szReqPort, szNewLine, nContentLength, szNewLine, szNewLine);

	if((*szRequest = (char*) calloc(strlen(http_header) + nContentLength + 1, 1)) == NULL)		
	{
// 		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
		nRet = -1;
		goto err;
	}	

	sprintf(*szRequest, "%s%s%s", http_header, szUriEncoded, szNewLine);	

	//PRINT_DEBUG(*szRequest);

err:
	if(szUriEncoded)
		free(szUriEncoded);

	return nRet;
}

int ParseXml(const char* szXML, Parser_PARAM *pParam)
{
	int nResult = 0;
	XML_Parser parser = NULL;
	enum XML_Status status;
	enum XML_Error errCode;    

	if((parser = XML_ParserCreate(NULL)) == NULL)    
	{
		nResult = -1;
		goto error;
	}

	XML_SetUserData(parser, pParam);
	XML_SetElementHandler(parser, OnElementStart, OnElementEnd);
	XML_SetCharacterDataHandler(parser, OnElementContents);

	//     status = XML_STATUS_OK;
	status = XML_Parse(parser, szXML, strlen(szXML), 0);

	if (status == XML_STATUS_ERROR)
	{
		errCode = XML_GetErrorCode(parser);
		printf("%s at line %u\n", XML_ErrorString(errCode), (unsigned)XML_GetCurrentLineNumber(parser));
		nResult = -1;
	}

error :
	XML_ParserFree(parser);

	return nResult;
}

void FreeParam(Parser_PARAM *pParam)
{
	if(pParam != NULL)
	{
		if(pParam->response.pDn != NULL)
			free(pParam->response.pDn);
		if(pParam->response.pKeyAlgo != NULL)
			free(pParam->response.pKeyAlgo);
		if(pParam->response.pKeyLength != NULL)
			free(pParam->response.pKeyLength);
		if(pParam->response.pCert != NULL)
			free(pParam->response.pCert);
		if(pParam->response.pAuthKey != NULL)
			free(pParam->response.pAuthKey);

		memset(pParam, 0x00, sizeof(Parser_PARAM));
	}
}

int UriEncode(char *str, char **ppEncoded)
{
	int nRet = 0;
	char buf[2+1];
	unsigned char c;
	int i, j;

	if(str == NULL)
	{
		nRet = -1;
		goto err;
	}

	if((*ppEncoded = (char *)malloc((strlen(str) * 3) + 1)) == NULL)
	{
		nRet = -1;
		goto err;
	}

	for(i = j = 0; str[i]; i++) 
	{
		c = (unsigned char)str[i];
		if((c >= '0') && (c <= '9')) (*ppEncoded)[j++] = c;
		else if((c >= 'A') && (c <= 'Z')) (*ppEncoded)[j++] = c;
		else if((c >= 'a') && (c <= 'z')) (*ppEncoded)[j++] = c;
		else if((c == '@') || (c == '.') || (c == '/') || (c == '\\')
			|| (c == '-') || (c == '_') || (c == ':') ) 
			(*ppEncoded)[j++] = c;
		else 
		{
			sprintf(buf, "%02x", c);
			(*ppEncoded)[j++] = '%';
			(*ppEncoded)[j++] = buf[0];
			(*ppEncoded)[j++] = buf[1];
		}
	}
	(*ppEncoded)[j] = '\0';
err:

	return nRet;
}

int UriEncodeValue(char *str, char **ppEncoded)
{
	int nRet = 0;
	int nCopiedLen = 0, nTotalLen = 0;
	char *pToken = NULL;
	char *szBuff = NULL;
	char seperate[] = "&";


	if((szBuff = (char*)calloc(strlen(str) + 1, 1)) == NULL)
	{
		nRet = -1;
		goto err;
	}
	memcpy(szBuff, str, strlen(str));

	pToken = strtok(szBuff, seperate);

	while(pToken != NULL)
	{
		char *pPos = strstr(pToken, "=");
		char *pEncoded = NULL;
		int nValueLen = pPos - pToken + 1;		

		if((nRet = UriEncode(pPos+1, &pEncoded)) != 0)
			goto err;

		nTotalLen += nValueLen + strlen(pEncoded);

		if(*ppEncoded == NULL)
		{
			if((*ppEncoded = (char*)calloc(nTotalLen + 1, 1)) == NULL)
			{
				nRet = -1;
				goto err;
			}

			memcpy(*ppEncoded, pToken, nValueLen);
			memcpy(*ppEncoded + nValueLen, pEncoded, strlen(pEncoded));
		}
		else
		{
			char *pTemp = NULL;

			nTotalLen += 1;	//for "&"

			if((pTemp = (char*)calloc(nTotalLen + 1, 1)) == NULL)
			{
				nRet = -1;
				goto err;
			}
			memcpy(pTemp, *ppEncoded, strlen(*ppEncoded));
			memcpy(pTemp + strlen(*ppEncoded), "&", 1);
			free(*ppEncoded);
			*ppEncoded = pTemp;

			memcpy(*ppEncoded + strlen(*ppEncoded), pToken, nValueLen);
			memcpy(*ppEncoded + strlen(*ppEncoded), pEncoded, strlen(pEncoded));
		}

		if(pEncoded != NULL)
			free(pEncoded);

		pToken = strtok(NULL, seperate);
	}

err:
	
	return nRet;
}

void XMLCALL OnElementStart(void* pParam, const XML_Char* pszName, const XML_Char* rgpszAttr[])
{
	Parser_PARAM* pMyParam = (Parser_PARAM*) pParam;

	if(_stricmp(pszName, "trustnetcas") == 0)
	{
		pMyParam->nFlag += ON_TRUSTNETCAS;
	}
	else if(_stricmp(pszName, "result") == 0)
	{
		pMyParam->nFlag += ON_RESULT;
	}
	else if(_stricmp(pszName, "dn") == 0)
	{
		pMyParam->nFlag += ON_DN;
	}
	else if(_stricmp(pszName, "keyalgo") == 0)
	{
		pMyParam->nFlag += ON_KEYALGO;
	}
	else if(_stricmp(pszName, "Keylength") == 0)
	{
		pMyParam->nFlag += ON_KEYLENGTH;
	}
	else if(_stricmp(pszName, "cert") == 0)
	{
		pMyParam->nFlag += ON_CERT;
	}
	else if(_stricmp(pszName, "authkey") == 0)
	{
		pMyParam->nFlag += ON_AUTHKEY;
	}
	// increase depth
	pMyParam->nDepth++;
}

void XMLCALL OnElementEnd(void* pParam, const XML_Char* pszName)
{
	Parser_PARAM* pMyParam = (Parser_PARAM*) pParam;

	if(_stricmp(pszName, "trustnetcas") == 0)
	{
		pMyParam->nFlag -= ON_TRUSTNETCAS;
	}
	else if(_stricmp(pszName, "result") == 0)
	{
		pMyParam->nFlag -= ON_RESULT;
	}
	else if(_stricmp(pszName, "dn") == 0)
	{
		pMyParam->nFlag -= ON_DN;
	}
	else if(_stricmp(pszName, "keyalgo") == 0)
	{
		pMyParam->nFlag -= ON_KEYALGO;
	}
	else if(_stricmp(pszName, "Keylength") == 0)
	{
		pMyParam->nFlag -= ON_KEYLENGTH;
	}
	else if(_stricmp(pszName, "cert") == 0)
	{
		pMyParam->nFlag -= ON_CERT;
	}
	else if(_stricmp(pszName, "authkey") == 0)
	{
		pMyParam->nFlag -= ON_AUTHKEY;
	}

	pMyParam->nDepth--;

}

void XMLCALL OnElementContents(void* pParam, const XML_Char* pContents, int nLen)
{
	Parser_PARAM* pMyParam = (Parser_PARAM*) pParam;	

	if(pMyParam->nFlag & ON_RESULT)
	{
		char szTemp[256] = "";
		memcpy(szTemp, pContents, nLen);
		pMyParam->nResult = strtol(szTemp, NULL, 10);
	}
	else if(pMyParam->nFlag & ON_DN && pMyParam->nResult == 0)
	{
		if((pMyParam->response.pDn = (char*)calloc(nLen + 1, 1)) != NULL)
			memcpy(pMyParam->response.pDn, pContents, nLen);		
	}
	else if(pMyParam->nFlag & ON_KEYALGO && pMyParam->nResult == 0)
	{
		if((pMyParam->response.pKeyAlgo = (char*)calloc(nLen + 1, 1)) != NULL)
			memcpy(pMyParam->response.pKeyAlgo, pContents, nLen);		
	}
	else if(pMyParam->nFlag & ON_KEYLENGTH && pMyParam->nResult == 0)
	{
		if((pMyParam->response.pKeyLength = (char*)calloc(nLen + 1, 1)) != NULL)
			memcpy(pMyParam->response.pKeyLength, pContents, nLen);		
	}
	else if(pMyParam->nFlag & ON_CERT && pMyParam->nResult == 0)
	{
		if((pMyParam->response.pCert = (char*)calloc(nLen + 1, 1)) != NULL)
			memcpy(pMyParam->response.pCert, pContents, nLen);		
	}
	else if(pMyParam->nFlag & ON_AUTHKEY && pMyParam->nResult == 0)
	{
		if((pMyParam->response.pAuthKey = (char*)calloc(nLen + 1, 1)) != NULL)
			memcpy(pMyParam->response.pAuthKey, pContents, nLen);		
	}
}