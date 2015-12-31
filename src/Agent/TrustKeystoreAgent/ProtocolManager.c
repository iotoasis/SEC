#include"ProtocolManager.h"

int TK_ParseResponse(char* szResponse, OP_RESPONSE *pResponse)
{
	int nRet = 0;
	Parser_PARAM param;
	Key *pKey = NULL;
	KeyList * pKeyList = NULL;

	memset(&param, 0x00, sizeof(Parser_PARAM));

	PRINT_DEBUG("TK_ParseResponse Start.");

#ifndef NO_XML
	if((nRet = ParseXml(szResponse, &param)) != TK_SUCCESS)
	{
		goto error;
	}
	PRINT_DEBUG("ParseXml OK.");
#else
	if((nRet = ParseNoXml(szResponse, &param)) != TK_SUCCESS)
	{
		goto error;
	}
	PRINT_DEBUG("ParseNoXml OK.");
#endif
	if(param.nResult == TK_SUCCESS)
	{
		memcpy(pResponse, &param.response, sizeof(OP_RESPONSE));
	}
	else
	{
		nRet = g_nAgentErrorCode = param.nResult;
	}

	PRINT_DEBUG("TK_ParseResponse Success");
error:	

	PRINT_DEBUG("TK_ParseResponse End.\n");

	return nRet;
}

#ifndef NO_XML

void XMLCALL OnElementStart(void* pParam, const XML_Char* pszName, const XML_Char* rgpszAttr[])
{
    Parser_PARAM* pMyParam = (Parser_PARAM*) pParam;

	if(_stricmp(pszName, "TrustKeystore") == 0)
	{
		pMyParam->nFlag += ON_TRUSTKEYSTORE;
	}
	else if(_stricmp(pszName, "OPCode") == 0)
	{
		pMyParam->nFlag += ON_OPCODE;
	}
	else if(_stricmp(pszName, "Result") == 0)
	{
		pMyParam->nFlag += ON_RESULT;
	}
	else if(_stricmp(pszName, "KeyStruct") == 0)
	{
		pMyParam->nFlag += ON_KEYSTRUCT;
		// Key memory 할당
		if(pMyParam->response.keyList.pKey == NULL && pMyParam->response.keyList.nKeyCount == 0)
		{
			if((pMyParam->response.keyList.pKey = (Key*) TK_MemAlloc(sizeof(Key))) == NULL)
			{
				g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
				return;
			}
		}
		else
		{
			TK_ReAlloc(pMyParam->response.keyList.pKey, sizeof(Key) * (pMyParam->response.keyList.nKeyCount + 1));

			if(pMyParam->response.keyList.pKey == NULL)
			{
				g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
				return;
			}

		}
	}
	else if(_stricmp(pszName, "KeyId") == 0)
	{
		pMyParam->nFlag += ON_KEYID;
	}
	else if(_stricmp(pszName, "KeyValue") == 0)
	{
		pMyParam->nFlag += ON_KEYVALUE;
	}
	else if(_stricmp(pszName, "KeyType") == 0)
	{
		pMyParam->nFlag += ON_KEY_TYPE;
	}	
	else if(_stricmp(pszName, "KeyAlgo") == 0)
	{
		pMyParam->nFlag += ON_KEYALGO;
	}
	else if(_stricmp(pszName, "OPMode") == 0)
	{
		pMyParam->nFlag += ON_OPMODE;
	}
	else if(_stricmp(pszName, "ExposeLevel") == 0)
	{
		pMyParam->nFlag += ON_EXPOSELEVEL;
	}
	else if(_stricmp(pszName, "ValidStart") == 0)
	{
		pMyParam->nFlag += ON_VALIDSTART;
	}
	else if(_stricmp(pszName, "ValidEnd") == 0)
	{
		pMyParam->nFlag += ON_VALIDEND;
	}
	else if(_stricmp(pszName, "KeyHmac") == 0)
	{
		pMyParam->nFlag += ON_KEYHMAC;
	}
	else if(_stricmp(pszName, "EncText") == 0)
	{
		pMyParam->nFlag += ON_ENCTEXT;
	}
	else if(_stricmp(pszName, "DecText") == 0)
	{
		pMyParam->nFlag += ON_DECTEXT;
	}
	else if(_stricmp(pszName, "ErrorMessage") == 0)
	{
		pMyParam->nFlag += ON_ERRORMESSAGE;
	}


	// increase depth
    pMyParam->nDepth++;
}

void XMLCALL OnElementEnd(void* pParam, const XML_Char* pszName)
{
    Parser_PARAM* pMyParam = (Parser_PARAM*) pParam;

	if(_stricmp(pszName, "TrustKeystore") == 0)
	{
		pMyParam->nFlag -= ON_TRUSTKEYSTORE;
	}
	else if(_stricmp(pszName, "OPCode") == 0)
	{
		pMyParam->nFlag -= ON_OPCODE;
	}
	else if(_stricmp(pszName, "Result") == 0)
	{
		pMyParam->nFlag -= ON_RESULT;
	}
	else if(_stricmp(pszName, "KeyStruct") == 0)
	{
		pMyParam->nFlag -= ON_KEYSTRUCT;
		pMyParam->response.keyList.nKeyCount++;
	}
	else if(_stricmp(pszName, "KeyId") == 0)
	{
		pMyParam->nFlag -= ON_KEYID;
	}
	else if(_stricmp(pszName, "KeyValue") == 0)
	{
		pMyParam->nFlag -= ON_KEYVALUE;
	}
	else if(_stricmp(pszName, "KeyType") == 0)
	{
		pMyParam->nFlag -= ON_KEY_TYPE;
	}
	else if(_stricmp(pszName, "KeyAlgo") == 0)
	{
		pMyParam->nFlag -= ON_KEYALGO;
	}
	else if(_stricmp(pszName, "OPMode") == 0)
	{
		pMyParam->nFlag -= ON_OPMODE;
	}
	else if(_stricmp(pszName, "ExposeLevel") == 0)
	{
		pMyParam->nFlag -= ON_EXPOSELEVEL;
	}
	else if(_stricmp(pszName, "ValidStart") == 0)
	{
		pMyParam->nFlag -= ON_VALIDSTART;
	}
	else if(_stricmp(pszName, "ValidEnd") == 0)
	{
		pMyParam->nFlag -= ON_VALIDEND;
	}
	else if(_stricmp(pszName, "KeyHmac") == 0)
	{
		pMyParam->nFlag -= ON_KEYHMAC;
	}
	else if(_stricmp(pszName, "EncText") == 0)
	{
		pMyParam->nFlag += ON_ENCTEXT;
	}
	else if(_stricmp(pszName, "DecText") == 0)
	{
		pMyParam->nFlag += ON_DECTEXT;
	}
	else if(_stricmp(pszName, "ErrorMessage") == 0)
	{
		pMyParam->nFlag += ON_ERRORMESSAGE;
	}

    pMyParam->nDepth--;

}

void XMLCALL OnElementContents(void* pParam, const XML_Char* pContents, int nLen)
{
    Parser_PARAM* pMyParam = (Parser_PARAM*) pParam;	
	
	if(pMyParam->nFlag & ON_OPCODE)
	{
		char szTemp[256] = "";
		memcpy(szTemp, pContents, nLen);
		pMyParam->nOPCode = strtol(szTemp, NULL, 10);
	}
	else if(pMyParam->nFlag & ON_RESULT)
	{
		char szTemp[256] = "";
		memcpy(szTemp, pContents, nLen);
		pMyParam->nResult = strtol(szTemp, NULL, 10);
	}
	else if(pMyParam->nFlag & ON_KEYSTRUCT && pMyParam->nResult == TK_SUCCESS)
	{
		Key	*pKey = pMyParam->response.keyList.pKey;
		int	nKeyCount = pMyParam->response.keyList.nKeyCount;

		if(pMyParam->nFlag & ON_KEYID)
		{			
 			memcpy(pKey[nKeyCount].key_id, pContents, nLen);
		}
		if(pMyParam->nFlag & ON_KEYVALUE)
		{
			memcpy(pKey[nKeyCount].enc_key_value, pContents, nLen);
		}
		if(pMyParam->nFlag & ON_KEY_TYPE)
		{
			memcpy(pKey[nKeyCount].key_Type, pContents, nLen);
		}
		if(pMyParam->nFlag & ON_KEYALGO)
		{
			memcpy(pKey[nKeyCount].key_algo, pContents, nLen);
		}
		if(pMyParam->nFlag & ON_OPMODE)
		{
			memcpy(pKey[nKeyCount].op_mode, pContents, nLen);
		}
		if(pMyParam->nFlag & ON_EXPOSELEVEL)
		{
			memcpy(pKey[nKeyCount].expose_level, pContents, nLen);
		}
		if(pMyParam->nFlag & ON_VALIDSTART)
		{
			memcpy(pKey[nKeyCount].valid_start, pContents, nLen);
		}
		if(pMyParam->nFlag & ON_VALIDEND)
		{
			memcpy(pKey[nKeyCount].valid_end, pContents, nLen);
		}
		if(pMyParam->nFlag & ON_KEYHMAC)
		{
			memcpy(pKey[nKeyCount].key_hmac, pContents, nLen);
		}
	}
	else if(pMyParam->nFlag & ON_ENCTEXT && pMyParam->nResult == TK_SUCCESS)
	{
		if((pMyParam->response.pszText = (char*) TK_MemAlloc(nLen + 1)) != NULL)
			memcpy(pMyParam->response.pszText, pContents, nLen);
	}
	else if(pMyParam->nFlag & ON_DECTEXT && pMyParam->nResult == TK_SUCCESS)
	{
		if((pMyParam->response.pszText = (char*) TK_MemAlloc(nLen + 1)) != NULL)
			memcpy(pMyParam->response.pszText, pContents, nLen);
	}
	else if(pMyParam->nResult != TK_SUCCESS && pMyParam->nFlag & ON_ERRORMESSAGE)
	{	
		int nlen = ERRORMSG_LEN < nLen ? ERRORMSG_LEN : nLen;
		memset(g_szAgentErrorMsg, 0x00, sizeof(g_szAgentErrorMsg));
		memcpy(g_szAgentErrorMsg, pContents, nlen);
	}
}

int ParseXml(const char* szXML, Parser_PARAM *pParam)
{
	int nResult = 0;
    XML_Parser parser;
    enum XML_Status status;
    enum XML_Error errCode;    

    if((parser = XML_ParserCreate(NULL)) == NULL)    
    {
        nResult = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_PARSEXML_EXPAT_PARSERCREATE;
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
		nResult = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_PARSEXML_EXPAT_PARSE;
    }
	
error :
	XML_ParserFree(parser);

    return nResult;
}
#else
int ParseNoXml(char* szNoXML, Parser_PARAM *pParam)
{
	int nRet = 0;
	char seperate[] = "|";
	char *pToken = NULL;

	// OPCode+'|'+Result+'|'+Response
	
	if((pToken = TK_Tokenizer(szNoXML, seperate)) == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_PARSENOXML_PARSE;
		goto error;
	}
	pParam->nOPCode = strtol(pToken, NULL, 10);
	if((pToken = TK_Tokenizer(NULL, seperate)) == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_PARSENOXML_PARSE;
		goto error;
	}
	pParam->nResult = strtol(pToken, NULL, 10);

	if((pToken = TK_Tokenizer(NULL, seperate)) == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_PARSENOXML_PARSE;
		goto error;
	}

	if(pParam->nResult == 0)
	{
#define KEY_META_DATA_CNT 9

		int nContent = 0;

		switch(pParam->nOPCode)
		{
		case OP_RESPONSE_KEY:
			do 
			{
				KeyList *pKeyList = &pParam->response.keyList;

				switch(nContent % KEY_META_DATA_CNT)
				{
				case 0:			// keyid
					if(pKeyList->pKey == NULL && pKeyList->nKeyCount == 0)
					{
						if((pKeyList->pKey = (Key*)TK_MemAlloc(sizeof(Key))) == NULL)
						{
							nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
							goto error;
						}
					}
					else
					{
						if((pKeyList->pKey = (Key*)TK_ReAlloc(pKeyList->pKey, (pKeyList->nKeyCount + 1) * sizeof(Key))) == NULL)
						{
							nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_REALLOC;
							goto error;
						}
					}					
					strncpy(pKeyList->pKey[pKeyList->nKeyCount].key_id, pToken, sizeof(pKeyList->pKey[pKeyList->nKeyCount].key_id) -1);					
					break;
				case 1:			// value
					memcpy(pKeyList->pKey[pKeyList->nKeyCount].enc_key_value, pToken, strlen(pToken));
					break;
				case 2:			// type
					memcpy(pKeyList->pKey[pKeyList->nKeyCount].key_Type, pToken, strlen(pToken));
					break;
				case 3:			// algo
					memcpy(pKeyList->pKey[pKeyList->nKeyCount].key_algo, pToken, strlen(pToken));
					break;
				case 4:			// opmode (optional)
					memcpy(pKeyList->pKey[pKeyList->nKeyCount].op_mode, pToken, strlen(pToken));					
					break;					
				case 5:			// expose level
					memcpy(pKeyList->pKey[pKeyList->nKeyCount].expose_level, pToken, strlen(pToken));					
					break;
				case 6:			// valid_start
					memcpy(pKeyList->pKey[pKeyList->nKeyCount].valid_start, pToken, strlen(pToken));					
					break;
				case 7:			// valid_end
					memcpy(pKeyList->pKey[pKeyList->nKeyCount].valid_end, pToken, strlen(pToken));					
					break;
				case 8:			// key_hmac
					memcpy(pKeyList->pKey[pKeyList->nKeyCount].key_hmac, pToken, strlen(pToken));
					pKeyList->nKeyCount++;
					break;
				}
				nContent++;
			} while (pToken = TK_Tokenizer(NULL, seperate));			

			break;
		case OP_RESPONSE_ENCRYPT:
		case OP_RESPONSE_DECRYPT:
			if((pParam->response.pszText = (char*)TK_MemAlloc(strlen(pToken) + 1)) == NULL)
			{
				nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
				goto error;
			}
			memcpy(pParam->response.pszText, pToken, strlen(pToken));

			break;
		default:
			nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_PARSENOXML_INVALID_OPCODE;
			goto error;

			break;
		}
	}
	else
	{
		// result가 0이 아닐 경우 g_szAgentErrorMsg에 에러 메시지를 저장한다.(서버 에러)
		memset(g_szAgentErrorMsg, 0x00, sizeof(g_szAgentErrorMsg));
		strncpy(g_szAgentErrorMsg, pToken, sizeof(g_szAgentErrorMsg)-1);			
	}

error:
	return nRet;
}
#endif // NO_XML


int TK_Indirect_MakeTLV(int nTag, char* value, int lenth, UString *pusTLV)
{
	int nRet = 0;

	if(lenth > 65535)
	{
		// value is too long
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_INDIRECT_MAKETLV_TOO_LONG_LENGTH;
		goto error;
	}

	if((nRet = TK_Set_UString(pusTLV, NULL, 1 + 2 + lenth)) != TK_SUCCESS) // tag + length + value
		goto error;

	pusTLV->value[0] = nTag;
	pusTLV->value[1] = ((0xFF00 & lenth) >> 8);
	pusTLV->value[2] = (0x00FF & lenth);

	memcpy(&(pusTLV->value[3]), value, lenth);

error:

	return nRet;
}

int TK_Indirect_PaseTLV(int nTag, char* TLV, int TLVlen, UString *pusValue)
{

	int nRet = 0;
	int nCurPos = 0;

	while(nCurPos < TLVlen)
	{
		unsigned char nCurTag = TLV[nCurPos];
		int nCurLen = (TLV[nCurPos+1] << 8) + TLV[nCurPos+2];
		
		switch(nCurTag)
		{
		case IND_TAG_DEVICEID:
		case IND_TAG_RANDOM:
		case IND_TAG_ENCRANDOM:
		case IND_TAG_ENCKEY:
		case IND_TAG_KEYALGO:
		case IND_TAG_KEYOPMODE:
		case IND_TAG_KEYID:
		case IND_TAG_ERRORCODE:
			break;

		default:
			// TLV tag error!
			nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_INDIRECT_PASETLV_INVALID_TAG;
			goto error;
		}

		if(nCurTag == (unsigned char)nTag)
		{
			if(nCurLen > 0)
			{
				if((nRet = TK_Set_UString(pusValue, &TLV[nCurPos + 3], nCurLen)) != TK_SUCCESS)
					goto error;
			}
			else
			{
				// length가 0일 경우에는 크기 1의 빈 메모리 할당해줌
				// opmode가 없는 key의 경우 길이가 0으로 넘어옴.
				if((nRet = TK_Set_UString(pusValue, NULL, 1)) != TK_SUCCESS)
					goto error;
			}	

			break;
		}
		else
		{
			nCurPos += (1 + 2 + nCurLen);	// tag + length + value
		}
	}

	if(pusValue->value == NULL || pusValue->length == 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_INDIRECT_PASETLV_TAG_NOT_FOUND;
		goto error;
	}

error:

	return nRet;
}
