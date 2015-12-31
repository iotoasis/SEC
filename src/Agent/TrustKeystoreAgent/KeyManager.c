#include "KeyManager.h"


int	g_nAgentErrorCode = 0;
char	g_szAgentErrorMsg[255 + 1] = {0};

//////////////////////////////////////////////////////////////////////////
// int KM_GetKey(Agent_Ctx *pContext, char* szKeyID, Key *pKey)
// 설명 : memory, DBFile, KMS에서 키를 가져와 복호화 해서 리턴.
// Input : Agent Context, KeyID
// Output : KeyStruct
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int KM_GetKey(Agent_Ctx *pContext, char* szKeyID, Key *pKey)
{
	int nRet = 0;
	Key storeKey;

	memset(&storeKey, 0x00, sizeof(Key));

	PRINT_DEBUG("KM_GetKey Start.");

	// Memory 체크
	if((nRet = KM_GetKeyFromMemory(pContext, szKeyID, pKey)) != TK_SUCCESS)
	{
		// KeyDB File이 존재하는 경우 Key DB에서 Key를 가져옴
		if((nRet = KM_CheckKeyDBFile(pContext)) == TK_SUCCESS)
		{
			if((nRet = KM_GetKeyFromKeyDBFile(pContext, szKeyID, pKey)) != TK_SUCCESS)
				goto error;		
		}
		else
		{
			// KMS 체크
			if((nRet = KM_GetKeyFromKMS(pContext, szKeyID, pKey)) != TK_SUCCESS)
				goto error;
		}
		// Key HMAC 체크
		if((nRet = KM_VerifyKeyHMAC(pContext, pKey)) != TK_SUCCESS)
			goto error;
		// DB 또는 KMS에서 키를 가져 온 경우, 키값을 암호화 하여 메모리에 저장한다.
		memcpy(&storeKey, pKey, sizeof(Key));		
		if((nRet = KM_EncryptKey(pContext, &storeKey)) != TK_SUCCESS)
			goto error;
		if((nRet = KM_SetKeyIntoMemory(pContext, &storeKey)) != TK_SUCCESS)
			goto error;
	}

	PRINT_DEBUG("KM_GetKey Success.");

error:
	PRINT_DEBUG("KM_GetKey End.\n");
	return nRet;
}
//////////////////////////////////////////////////////////////////////////
// int KM_CheckKeyDBFile(Agent_Ctx *pContext)
// 설명 : KeyDB 파일이 존재하는지 여부 체크
// Input : Agent Context
// Output :
// Return : 0(파일 존재), -1(파일 없음)
//////////////////////////////////////////////////////////////////////////
int KM_CheckKeyDBFile(Agent_Ctx *pContext)
{
	int nRet = 0;
	char szKeyDBPATH[MAX_PATH] = "";
	FILE *pfile = NULL;

#ifndef NO_KEY_DB
	sprintf(szKeyDBPATH, "%s/%s", pContext->pConfig->agentHomeDir, KEY_DB_FILE_NAME);

	// file check
	if((pfile = fopen(szKeyDBPATH, "r")) == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_CHECKKEYDBFILE_FILE_NOT_FOUND;
		goto error;
	}

	PRINT_DEBUG("KM_CheckKeyDBFile Success.");

error:
	
	if(pfile)
		fclose(pfile);
#else
	// Key DB 파일을 사용하지 않는 경우.
	nRet = -1;
#endif
	return nRet;
}
//////////////////////////////////////////////////////////////////////////
// int KM_GetKeyFromKeyDBFile(Agent_Ctx *pContext, char* szKeyID, Key *pKey)
// 설명 : KeyDB 파일에서 입력받은 키 아이디에 해당하는 키 구조체를 가져옴
// 복호화 된 키 값과 길이를 리턴.
// Input : Agent Context, KeyID
// Output : KeyStruct
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int KM_GetKeyFromKeyDBFile(Agent_Ctx *pContext, char* szKeyID, Key *pKey)
{
	int nRet = 0;
	char szKeyDBFile[MAX_PATH] = "";
	UString hmacKey;
	UString kek;
	UString decodedKeyValue;
	UString decKeyValue;

	memset(&hmacKey, 0x00, sizeof(UString));
	memset(&kek, 0x00, sizeof(UString));
	memset(&decodedKeyValue, 0x00, sizeof(UString));
	memset(&decKeyValue, 0x00, sizeof(UString));

	PRINT_DEBUG("KM_GetKeyFromKeyDBFile Start.");

	sprintf(szKeyDBFile, "%s/%s", pContext->pConfig->agentHomeDir, KEY_DB_FILE_NAME);

	if((nRet = TK_GetKeyFromDB(szKeyDBFile, szKeyID, pKey)) != TK_SUCCESS)
		goto error;
	
	// HMAC Key 생성. HMAC Key = ,sha256(IP):4,1,3,2
	{
		UString hmacKeyMaterial;

		hmacKeyMaterial.value = pContext->pConfig->agentIP;
		hmacKeyMaterial.length = strlen(pContext->pConfig->agentIP);

		if((nRet = KM_Make_KeyFromMaterial(&hmacKeyMaterial, &hmacKey)) != TK_SUCCESS)
			goto error;
	}

	// KEK 생성 kek = HMAC(kek material). kek material = ip+패딩.
	{
		UString kekMaterial;
		char szKEKMaterial[KEK_MATERIAL_LEN] = "";

		memcpy(szKEKMaterial, IP_PADDING, strlen(IP_PADDING));
		memcpy(szKEKMaterial, pContext->pConfig->agentIP, strlen(pContext->pConfig->agentIP));

		kekMaterial.value = szKEKMaterial;
		kekMaterial.length = sizeof(szKEKMaterial);

		if((nRet = TK_Make_HMAC(SHA256, &hmacKey, &kekMaterial, &kek)) != TK_SUCCESS)
			goto error;
	}

	// 키값 b64decode
	if((nRet = TK_Base64_Decode(pKey->enc_key_value, &decodedKeyValue)) != TK_SUCCESS)
		goto error;
	// 키값 복호화	
	if((nRet = TK_Aes128_Decrypt(&decKeyValue, &decodedKeyValue, &kek)) != TK_SUCCESS)
		goto error;
	// 키 구조체에 복호화 키값과 길이 세팅
	memset(pKey->enc_key_value, 0x00, sizeof(pKey->enc_key_value));
	memcpy(pKey->enc_key_value, decKeyValue.value, decKeyValue.length);
	pKey->key_size = decKeyValue.length;

	PRINT_DEBUG("KM_GetKeyFromKeyDBFile Success.");

error:

	TK_Free_UString(&hmacKey);
	TK_Free_UString(&kek);
	TK_Free_UString(&decodedKeyValue);
	TK_Free_UString(&decKeyValue);

	PRINT_DEBUG("KM_GetKeyFromKeyDBFile End.");

	return nRet;
}
//////////////////////////////////////////////////////////////////////////
// int KM_GetKeyFromMemory(Agent_Ctx *pContext, char* szKeyID, Key *pKey = NULL)
// 설명 : 입력받은 키 아이디에 해당하는 키 구조체를 메모리에서 리턴
// 복호화 된 키 값과 길이를 리턴.
// pKey == NULL이면 메모리에 ID가 있는지 여부만 체크
// Input : Agent Context, KeyID
// Output : KeyStruct
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int KM_GetKeyFromMemory(Agent_Ctx *pContext, char* szKeyID, Key *pKey)
{
	int nRet = 0;
	int i = 0;

	PRINT_DEBUG("KM_GetKeyFromMemory Start.");

	if(szKeyID == NULL || strlen(szKeyID) == 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_GETKEYFROMMEMORY_ARG_ERROR;
		goto error;
	}

	if(pContext->pKeyList->nKeyCount == 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_GETKEYFROMMEMORY_NO_KEY;
		goto error;
	}

	// 메모리에서 관리하는 키의 갯수가 많지 않을 것으로 예상되어 순차탐색으로 키를 검색.
	for(i = 0; i < pContext->pKeyList->nKeyCount; i++)
	{
		size_t nCurKeyIDLen = strlen(pContext->pKeyList->pKey[i].key_id);
		int nCompareKeyIDLen = nCurKeyIDLen > strlen(szKeyID) ? nCurKeyIDLen : strlen(szKeyID);

		if(strncmp(pContext->pKeyList->pKey[i].key_id, szKeyID, nCompareKeyIDLen) == 0)
		{
			// pKey가 NULL일 경우 키값을 반환 하지는 않고, return 0로 키가 있음을 알려주기만 한다.
			if(pKey != NULL)
			{
				memcpy(pKey, &(pContext->pKeyList->pKey[i]), sizeof(Key));
				// 키값 복호화
				if((nRet = KM_DecryptKey(pContext, pKey)) != TK_SUCCESS)
					goto error;
			}			
			break;
		}
		else
		{
			// key id를 찾지 못함
			if(i == pContext->pKeyList->nKeyCount -1 )
			{				
				nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_GETKEYFROMMEMORY_NOT_FOUND_KEYID;
				goto error;
			}
		}
	}

	PRINT_DEBUG("KM_GetKeyFromMemory Success.");

error:

	PRINT_DEBUG("KM_GetKeyFromMemory End.\n");
	return nRet;
}
//////////////////////////////////////////////////////////////////////////
// int KM_SetKeyIntoMemory(Agent_Ctx *pContext, Key *pKey)
// 설명 : 메모리에 키 구조체 저장
// Input : Agent Context, KeyStruct
// Output :
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int KM_SetKeyIntoMemory(Agent_Ctx *pContext, Key *pKey)
{
	int nRet = 0;
	int i = 0;

	PRINT_DEBUG("KM_SetKeyIntoMemory Start.");

	// Dynamic 키의 경우 메모리에 저장하지 않는다.
	if(strncmp(pKey->key_Type, "D", sizeof(pKey->key_Type)) == 0)
		goto error;

	if(pContext->pKeyList->pKey == NULL && pContext->pKeyList->nKeyCount == 0)
	{
		if((pContext->pKeyList->pKey = (Key*)TK_MemAlloc(sizeof(Key))) == NULL)		
		{
			nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
			goto error;
		}
		pContext->pKeyList->nKeyCount = 1;
		memcpy(pContext->pKeyList->pKey, pKey, sizeof(Key));
	}
	else
	{
		int nFindKey = 0;

		for(i = 0; i < pContext->pKeyList->nKeyCount; i++)
		{
			// 기존 메모리에 있는 키 중 같은 ID를 가진 키가 있는지 확인
			if(strncmp(pContext->pKeyList->pKey[i].key_id, pKey->key_id, sizeof(pContext->pKeyList->pKey[i].key_id)) == 0)
			{
				// ID가 같으면 덮어쓴다.
				memcpy(&pContext->pKeyList->pKey[i], pKey, sizeof(Key));
				nFindKey = 1;
				break;
			}
		}
		if(nFindKey == 0)
		{
			// 같은 ID가 없으면 추가한다.
			if((pContext->pKeyList->pKey = (Key*)TK_ReAlloc(pContext->pKeyList->pKey, sizeof(Key) * (pContext->pKeyList->nKeyCount + 1))) == NULL)				
			{
				nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_REALLOC;
				goto error;
			}
			memcpy(&pContext->pKeyList->pKey[pContext->pKeyList->nKeyCount++], pKey, sizeof(Key));
		}

	}
	PRINT_DEBUG("KM_SetKeyIntoMemory Success.");

error:

	PRINT_DEBUG("KM_SetKeyIntoMemory End.\n");

	return nRet;
}
//////////////////////////////////////////////////////////////////////////
// int KM_SetKeyListIntoMemory(Agent_Ctx *pContext, KeyList *pKeyList)
// 설명 : 메모리에 키 리스트 저장
// Input : Agent Context, KeyList
// Output :
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int KM_SetKeyListIntoMemory(Agent_Ctx *pContext, KeyList *pKeyList)
{
	int nRet = 0;
	int i = 0;

	if(pKeyList == NULL || pKeyList->pKey == NULL || pKeyList->nKeyCount == 0)
	{
		nRet = -1;
		goto error;
	}

	for(i = 0; i < pKeyList->nKeyCount; i++)
	{
		// 평문 키를 암호화 하여 저장.
		if((nRet = KM_EncryptKey(pContext, &pKeyList->pKey[i])) != TK_SUCCESS)
			goto error;
		if((nRet = KM_SetKeyIntoMemory(pContext, &pKeyList->pKey[i])) != TK_SUCCESS)
			goto error;
	}
error:
	return nRet;
}
//////////////////////////////////////////////////////////////////////////
// int KM_GetKeyFromKMS(Agent_Ctx *pContext, char* szKeyID, Key *pKey)
// 설명 : Kms에 키 아이디를 요청하고 키를 응답받음
// 복호화 된 키 값과 길이를 리턴.
// KeyID가 null일 경우 Agent가 사용 가능한 모든 키 리턴
// Input : Agent Context, Key
// Output : Key
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int KM_GetKeyFromKMS(Agent_Ctx *pContext, char* szKeyID, Key *pKey)
{
	int nRet = 0;	
	char *pReqMsg = NULL;
	char *pResMsg = NULL;
	OP_RESPONSE response;
	UString kek;
	UString decodedKeyValue;
	UString decKeyValue;

	memset(&response, 0x00, sizeof(OP_RESPONSE));
	memset(&kek, 0x00, sizeof(UString));
	memset(&decodedKeyValue, 0x00, sizeof(UString));
	memset(&decKeyValue, 0x00, sizeof(UString));
	
	PRINT_DEBUG("KM_GetKeyFromKMS Start.");

	if((nRet = KM_MakeRequest(pContext, OP_REQUEST_KEY, szKeyID, &pReqMsg)) != TK_SUCCESS)
		goto error;
	if((nRet = KM_RequestToKMS(pContext, pReqMsg, &pResMsg)) != TK_SUCCESS)
		goto error;
	if((nRet = TK_ParseResponse(pResMsg, &response)) != TK_SUCCESS)
		goto error;
	memcpy(pKey, &response.keyList.pKey[0], sizeof(Key));
	// KEK 생성
	{
		UString kekMaterial;
		kekMaterial.value = pKey->key_id;
		kekMaterial.length = strlen(pKey->key_id);

		if((nRet = KM_Make_KeyFromMaterial(&kekMaterial, &kek)) != TK_SUCCESS)
			goto error;
	}
	// 키값 b64decode
	if((nRet = TK_Base64_Decode(pKey->enc_key_value, &decodedKeyValue)) != TK_SUCCESS)
		goto error;
	// 키값 복호화	
	if((nRet = TK_Aes128_Decrypt(&decKeyValue, &decodedKeyValue, &kek)) != TK_SUCCESS)
		goto error;
	// 키 구조체에 복호화 키값과 길이 세팅
 	memset(pKey->enc_key_value, 0x00, sizeof(pKey->enc_key_value));
 	memcpy(pKey->enc_key_value, decKeyValue.value, decKeyValue.length);
	pKey->key_size = decKeyValue.length;

	PRINT_DEBUG("KM_GetKeyFromKMS Success");
error:

	TK_MemFree((void**)&pReqMsg);
	TK_MemFree((void**)&pResMsg);
	TK_MemFree((void**)&response.keyList.pKey);
	TK_Free_UString(&kek);
	TK_Free_UString(&decodedKeyValue);
	TK_Free_UString(&decKeyValue);

	PRINT_DEBUG("KM_GetKeyFromKMS End.\n");

	return nRet;
}
//////////////////////////////////////////////////////////////////////////
// int KM_GetKeyListFromKMS(Agent_Ctx *pContext, char* szKeyIDList, KeyList *pKeyList)
// 설명 : Kms에 키 아이디 리스트를 요청하고 키 리스트를 응답받음
// KeyIDList가 null일 경우 Agent가 사용 가능한 모든 키 리턴
// 사용 후 pKeyList->pKey 메모리 해제 해야 함.
// Input : Agent Context, KeyIDList
// Output : KeyList
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int KM_GetKeyListFromKMS(Agent_Ctx *pContext, char* szKeyIDList, KeyList *pKeyList)
{
	int nRet = 0;
	int i = 0;
	char *pReqMsg = NULL;
	char *pResMsg = NULL;
	OP_RESPONSE response;
	UString kek;
	UString decodedKeyValue;
	UString decKeyValue;
	
	memset(&response, 0x00, sizeof(OP_RESPONSE));
	memset(&kek, 0x00, sizeof(UString));
	memset(&decodedKeyValue, 0x00, sizeof(UString));
	memset(&decKeyValue, 0x00, sizeof(UString));

	if((nRet = KM_MakeRequest(pContext, OP_REQUEST_KEY, szKeyIDList, &pReqMsg)) != TK_SUCCESS)
		goto error;	
	if((nRet = KM_RequestToKMS(pContext, pReqMsg, &pResMsg)) != TK_SUCCESS)
		goto error;
	if((nRet = TK_ParseResponse(pResMsg, &response)) != TK_SUCCESS)
		goto error;
	memcpy(pKeyList, &response.keyList, sizeof(KeyList));
	
	for(i = 0; i < pKeyList->nKeyCount; i++)
	{
		// KEK 생성
		{
			UString kekMaterial;
			kekMaterial.value = pKeyList->pKey[i].key_id;
			kekMaterial.length = strlen(pKeyList->pKey[i].key_id);

			if((nRet = KM_Make_KeyFromMaterial(&kekMaterial, &kek)) != TK_SUCCESS)
				goto error;
		}

		// 키값 b64decode
		if((nRet = TK_Base64_Decode(pKeyList->pKey[i].enc_key_value, &decodedKeyValue)) != TK_SUCCESS)
			goto error;
		// 키값 복호화	
		if((nRet = TK_Aes128_Decrypt(&decKeyValue, &decodedKeyValue, &kek)) != TK_SUCCESS)
			goto error;
		// 키 구조체에 복호화 키값과 길이 세팅
		memset(pKeyList->pKey[i].enc_key_value, 0x00, sizeof(pKeyList->pKey[i].enc_key_value));
		memcpy(pKeyList->pKey[i].enc_key_value, decKeyValue.value, decKeyValue.length);
		pKeyList->pKey[i].key_size = decKeyValue.length;

		TK_Free_UString(&kek);
		TK_Free_UString(&decodedKeyValue);
		TK_Free_UString(&decKeyValue);
	}

error:
	TK_MemFree((void**)&pReqMsg);
	TK_MemFree((void**)&pResMsg);

	TK_Free_UString(&kek);
	TK_Free_UString(&decodedKeyValue);
	TK_Free_UString(&decKeyValue);

	return nRet;
}
//////////////////////////////////////////////////////////////////////////
// int KM_GetUpdateAvailableKeyIDList(Agent_Ctx *pContext, char* szKeyIDListIn, char* szKeyIDListOut)
// 설명 : KeyID리스트를 입력받아 그 중 업데이트가 가능한 KeyID리스트를 반환.
// szKeyIDListIn == null일 경우 메모리의 모든 KeyID 리스트 반환
// update 가능한 키가 없을 경우 szKeyIDListOut = NULL 반환
// Input : Agent Context, szKeyIDListIn(key_id+'|'+key_id+...)
// Output : szKeyIDListOut(key_id+'|'+key_id+...)
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int KM_GetUpdateAvailableKeyIDList(Agent_Ctx *pContext, char* szKeyIDListIn, char** szKeyIDListOut)
{
	int nRet = 0;
	int i = 0;
	char *pToken = NULL;
	char *szKeyIDList = NULL;
	char seperate[] = "|";

	if(szKeyIDListIn == NULL || strlen(szKeyIDListIn) == 0)	// 메모리 상의 전체 키 리스트 리턴.
	{
		for(i = 0; i < pContext->pKeyList->nKeyCount; i++)
		{
			char *pKey_id = pContext->pKeyList->pKey[i].key_id;

			if(*szKeyIDListOut == NULL)
			{
				if((*szKeyIDListOut = (char*)TK_MemAlloc(strlen(pKey_id) +1)) == NULL)				
				{
					nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
					goto error;
				}
				strncpy(*szKeyIDListOut, pKey_id, strlen(pKey_id));
			}
			else
			{
				if((*szKeyIDListOut = (char*)TK_ReAlloc(*szKeyIDListOut, TK_MemSize(*szKeyIDListOut) + strlen(pKey_id) +2)) == NULL) // +2 for '|' and \0
				{
					nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_REALLOC;
					goto error;
				}

				strcat(*szKeyIDListOut, "|");
				strcat(*szKeyIDListOut, pKey_id);				
			}
		}

	}
	else // 전달받은 키 중에 메모리상에 있는 키 리턴.
	{
		if((szKeyIDList = (char*) TK_MemAlloc(strlen(szKeyIDListIn)+1)) == NULL)
		{
			nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
			goto error;
		}
		strncpy(szKeyIDList, szKeyIDListIn, strlen(szKeyIDListIn));

		pToken = strtok(szKeyIDList, seperate);

		while(pToken != NULL)
		{
			if(KM_GetKeyFromMemory(pContext, pToken, NULL) == TK_SUCCESS)
			{
				if(*szKeyIDListOut == NULL)
				{
					if((*szKeyIDListOut = (char*)TK_MemAlloc(strlen(pToken) +1)) == NULL)
					{
						nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
						goto error;
					}
					strncpy(*szKeyIDListOut, pToken, strlen(pToken));
				}
				else
				{
					if((*szKeyIDListOut = (char*)TK_ReAlloc(*szKeyIDListOut, TK_MemSize(*szKeyIDListOut) + strlen(pToken) +2)) == NULL) // +2 for '|' and \0
					{
						nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_REALLOC;
						goto error;
					}
					sprintf(*szKeyIDListOut, "|%s", pToken);
				}
			}
			pToken = strtok(NULL, seperate);
		}
	}

	if(*szKeyIDListOut == NULL)
	{
		// 업데이트 가능한 키가 없음.
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_GET_UPDATEAVAILABLEKEYIDLIST_NOKEY;
	}
error:
	TK_MemFree((void**)&szKeyIDList);

	return nRet;
}

//////////////////////////////////////////////////////////////////////////
// int KeyStructToKeyInfo(KeyStruct *pKey, char* szKeyInfo)
// 설명 : 키 구조체를 입력받아 문자열 생성
// Input : Key 구조체
// Output : Key Info (KeyID+'|'+b64E(KeyValue)+'|'+KeyAlgo+'|'+OPMode)
// Return : 
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// int KM_MakeRequest(Agent_Ctx *pContext, int nOPCode, char* szArg, char*szRequest)
// 설명 : 서버에 요청하는 요청 메시지(http)를 만드는 함수
// Input : Agent Context, OPCode, Arguments
// Output : Request
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int KM_MakeRequest(Agent_Ctx *pContext, int nOPCode, char* szArg, char** szRequest)
{
	int nRet = 0;
	char http_header[256] = "";
	char http_msg[256] = "";
	char method[] = "POST";
	int nContentLength = 0;
		
	// common request header		
	sprintf(http_msg, "ProtocolVersion=%d&AgentID=%s&AgentCheckValue=%s&", TK_PROTOCOL_VERSION, pContext->pConfig->agentID, pContext->pConfig->agentHMAC);

	// request
	switch(nOPCode)
	{
	case OP_REQUEST_KEY:
	case OP_REQUEST_ENCRYPT:
	case OP_REQUEST_DECRYPT:		
		
		sprintf(http_msg + strlen(http_msg), "OPCode=%d&OPArg=", nOPCode);
		nContentLength = strlen(http_msg) + strlen(szArg) + strlen("\r\n");
		// make http header
		sprintf(http_header, "%s %s HTTP/1.1\r\nHost: %s:%s\r\nContent-Length: %d\r\n\r\n", method, KMS_REQPAGE, pContext->pConfig->kmsIP, pContext->pConfig->kmsPort, nContentLength);

		if((*szRequest = (char*) TK_MemAlloc(strlen(http_header) + nContentLength + 1)) == NULL)		
		{
			nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
			goto error;
		}	

		sprintf(*szRequest, "%s%s%s\r\n", http_header, http_msg, szArg);		

		break;
	default:
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MAKEREQUEST_INVALID_OPCODE;
		goto error;

		break;
	}
 	PRINT_DEBUG(*szRequest);

error:
	return nRet;
}

//////////////////////////////////////////////////////////////////////////
// int KM_RequestToKMS(Agent_Ctx *pContext, char* szSendMsg, char* szRecvMsg)
// 설명 : KMS 서버에 요청 메시지(SSL)를 보내고 응답 메시지를 받는 함수
// Input : Agent Context, SendMsg
// Output : RecvMsg
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int KM_RequestToKMS(Agent_Ctx *pContext, char* szSendMsg, char** szRecvMsg)
{
	int nRet = 0;
	int got = 0;
	char reply[1024+1] = {0};
	char *pRecv = NULL;
	int nRecvLen = 0;

	if((nRet = TK_Connect(pContext->sslCtx, pContext->pConfig->kmsIP, strtol(pContext->pConfig->kmsPort, NULL, 10), 0)) != TK_SUCCESS)
		goto error;

	if((nRet = TK_SEND(szSendMsg, strlen(szSendMsg))) != TK_SUCCESS)
		goto error;

	if((nRet = TK_HTTP_RECV(szRecvMsg, &nRecvLen)) != TK_SUCCESS)
		goto error;
	PRINT_DEBUG("Receive Message : ");
	PRINT_DEBUG(*szRecvMsg);

error:

	TK_Disconnect();
	return nRet;
}

int KM_VerifyKeyHMAC(Agent_Ctx *pContext, Key *pKey)
{
	int nRet = 0;
	char HMACInput[256] = {0};
	int nHMACInputLen = 0;
	UString usHMACKey;
	UString usHMACResult;
	char * pszHMACResultB64Enc = NULL;

	memset(&usHMACKey, 0x00, sizeof(UString));
	memset(&usHMACResult, 0x00, sizeof(UString));

	PRINT_DEBUG("KM_VerifyKeyHMAC Start.");

	if(pKey == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_VERIFYKEYHMAC_ARG_ERROR;
		goto error;
	}

	// make plain text	
	memcpy(HMACInput, pKey->key_id, strlen(pKey->key_id));
	nHMACInputLen = strlen(pKey->key_id);

	memcpy(HMACInput + nHMACInputLen, pKey->enc_key_value, pKey->key_size);	// enc_key_value = 복호화된 키 값
	nHMACInputLen += pKey->key_size;

	memcpy(HMACInput + nHMACInputLen, pKey->key_algo, strlen(pKey->key_algo));
	nHMACInputLen += strlen(pKey->key_algo);

	memcpy(HMACInput + nHMACInputLen, pKey->op_mode, strlen(pKey->op_mode));
	nHMACInputLen += strlen(pKey->op_mode);

	memcpy(HMACInput + nHMACInputLen, pKey->expose_level, strlen(pKey->expose_level));
	nHMACInputLen += strlen(pKey->expose_level);

	memcpy(HMACInput + nHMACInputLen, pKey->valid_start, strlen(pKey->valid_start));
	nHMACInputLen += strlen(pKey->valid_start);

	memcpy(HMACInput + nHMACInputLen, pKey->valid_end, strlen(pKey->valid_end));
	nHMACInputLen += strlen(pKey->valid_end);

	// make HMAC Key
	{
		UString usHMACKeyMaterial;
		usHMACKeyMaterial.value = pKey->key_id;
		usHMACKeyMaterial.length = strlen(pKey->key_id);

		if((nRet = KM_Make_KeyFromMaterial(&usHMACKeyMaterial, &usHMACKey)) != TK_SUCCESS)
			goto error;
	}
	// make HMAC
	{
		UString usHMACText;
		usHMACText.value = HMACInput;
		usHMACText.length = nHMACInputLen;
		
		if((nRet = TK_Make_HMAC(SHA256, &usHMACKey, &usHMACText, &usHMACResult)) != TK_SUCCESS)
			goto error;
	}
	// b64Encode HMAC
	if((nRet = TK_Base64_Encode(&usHMACResult, &pszHMACResultB64Enc)) != TK_SUCCESS)
		goto error;
	// compare HMAC
	if(strncmp(pszHMACResultB64Enc, pKey->key_hmac, strlen(pKey->key_hmac)) != 0)
	{
		// 검증 실패!
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_VERIFYKEYHMAC_VERIFY_ERROR;
		goto error;
	}

	PRINT_DEBUG("KM_VerifyKeyHMAC Success");

error:
	
	TK_Free_UString(&usHMACKey);
	TK_Free_UString(&usHMACResult);
	TK_MemFree((void**)&pszHMACResultB64Enc);

	PRINT_DEBUG("KM_VerifyKeyHMAC End.\n");

	return nRet;
}

int KM_VerifyKeyValidDate(Agent_Ctx *pContext, Key *pKey)
{
	int nRet = 0;

	time_t t = time(0);   // get time now
	struct tm * now = localtime( & t );
	int nCurYear = 0, nCurMonth = 0, nCurDay = 0;
	int nDiffYear = 0, nDiffMonth = 0, nDiffDay = 0;	

	PRINT_DEBUG("KM_VerifyKeyValidDate Start.");

	if(strlen(pKey->valid_start) == 0 && strlen(pKey->valid_end))
		goto error;

	// 현재 로컬 시간 구하기.
	nCurYear = now->tm_year + 1900;
	nCurMonth = now->tm_mon + 1;
	nCurDay = now->tm_mday;

	// valid_start와 비교.
	if(strlen(pKey->valid_start) > 0)
	{
		nDiffYear = strtol(pKey->valid_start, NULL, 10);
		nDiffMonth = strtol(&pKey->valid_start[5], NULL, 10);
		nDiffDay = strtol(&pKey->valid_start[8], NULL, 10);

		if(nCurYear < nDiffYear)
		{
			nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_VALIDDATE_BEFORE;
			goto error;
		}
		else if(nCurYear == nDiffYear)
		{
			if(nCurMonth < nDiffMonth)
			{
				nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_VALIDDATE_BEFORE;
				goto error;
			}
			else if(nCurMonth == nDiffMonth)
			{
				if(nCurDay < nDiffDay)
				{
					nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_VALIDDATE_BEFORE;
					goto error;
				}
			}
		}
	}
	// valid_end와 비교.
	if(strlen(pKey->valid_end) > 0)
	{
		nDiffYear = strtol(pKey->valid_end, NULL, 10);
		nDiffMonth = strtol(&pKey->valid_end[5], NULL, 10);
		nDiffDay = strtol(&pKey->valid_end[8], NULL, 10);

		if(nCurYear > nDiffYear)
		{
			nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_VALIDDATE_EXPIRED;
			goto error;
		}
		else if(nCurYear == nDiffYear)
		{
			if(nCurMonth > nDiffMonth)
			{
				nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_VALIDDATE_EXPIRED;
				goto error;
			}
			else if(nCurMonth == nDiffMonth)
			{
				if(nCurDay > nDiffDay)
				{
					nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_VALIDDATE_EXPIRED;
					goto error;
				}
			}
		}
	}

error:
	PRINT_DEBUG("KM_VerifyKeyValidDate End.");
	return nRet;

}

int KM_VerifyKeyExposeLevel(Agent_Ctx *pContext, Key *pKey, int nUsage)
{
	int nRet = 0;
	int nExposeLevel;

	// expose level 정보가 없을 경우 그냥 통과
	if(strlen(pKey->expose_level) == 0)
		goto error;

	nExposeLevel = strtol(pKey->expose_level, NULL, 10);

	PRINT_DEBUG("KM_VerifyKeyExposeLevel Start.");

	switch(nUsage)
	{
	case USE_KEY_SERVER_ONLY:
	case USE_KEY_IN_AGENT:
	case USE_KEY_OUT_OF_AGENT:
		break;
	default:
		// 정의되지 않은 키 용도
		nRet = TK_AGENT_ERROR_FAILED_EXPOSELEVEL_UNDEFINED_KEYUSAGE;
		goto error;
		break;;
	}

	if(nExposeLevel == USE_KEY_SERVER_ONLY)
	{
		// Critical Server error.
		nRet = TK_AGENT_ERROR_FAILED_EXPOSELEVEL_SERVER_ONLY_KEY;
	}
	else if(nExposeLevel < nUsage)
		nRet = TK_AGENT_ERROR_FAILED_EXPOSELEVEL;

error:

	PRINT_DEBUG("KM_VerifyKeyExposeLevel End.");

	return nRet;
}

int KM_InitComm(Agent_Ctx *pContext)
{
	int nRet = 0;
	PRINT_DEBUG("[ KM_InitComm ] Start.");

	if((nRet = TK_COMM_INIT(&pContext->sslCtx, SSL_SERVER_CA_CERT_NAME, pContext->pConfig->agentHomeDir)) != TK_SUCCESS)
		goto error;

	PRINT_DEBUG("KM_InitComm Success.");
error:

	PRINT_DEBUG("[ KM_InitComm ] End.\n");

	return nRet;
}

int KM_CheckCtx(Agent_Ctx *pContext)
{
	int nRet = 0;

	if(pContext == NULL || pContext->pConfig == NULL || pContext->pKeyList == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_CHECKCTX_INITIALIZE;
	}

	return nRet;
}
void KM_CtxFree(Agent_Ctx **ppContext)
{
	TK_COMM_FINAL(&(*ppContext)->sslCtx);

	if(*ppContext)
	{
		if((*ppContext)->pKeyList)
		{
			if((*ppContext)->pKeyList->pKey)
			{
				TK_MemFree((void**)&(*ppContext)->pKeyList->pKey);
			}
		}
		TK_MemFree((void**)&(*ppContext)->pKeyList);

		if((*ppContext)->pConfig)
		{
			TK_MemFree((void**)&(*ppContext)->pConfig);
		}
	}
	TK_MemFree((void**)ppContext);

	return;
}

int KM_SetConfig(Agent_Ctx *pContext, char *szConfPath)
{
	int		nRet = 0;
	FILE	*pfile = NULL;
	char	szConfFileName[MAX_PATH] = {0};
	char	szBuff[MAX_PATH] = {0};		// file read 버퍼
	char	seperate[] = "= \t\n\r";
	char	*pToken = NULL;
	char	*pNextToken = NULL;

	PRINT_DEBUG("KM_SetConfig Start.");

	if(pContext == NULL || pContext->pConfig == NULL || szConfPath == NULL || strlen(szConfPath) < 1)
	{
		PRINT_DEBUG("*** KM_SetConfig argument error.");
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_SETCONFIG_ARG_ERROR;
		goto error;
	}	

	strncpy(pContext->pConfig->agentHomeDir, szConfPath, sizeof(pContext->pConfig->agentHomeDir) -1);
 	sprintf(szConfFileName, "%s/%s", pContext->pConfig->agentHomeDir, AGENT_CONF_FILE_NAME);

	PRINT_DEBUG(szConfFileName);

	if((pfile = fopen(szConfFileName, "r")) == NULL)
	{
		PRINT_DEBUG("*** KM_SetConfig file open error.");
		
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_SETCONFIG_FILEOPEN;
		goto error;
	}
	while(!feof(pfile))
	{		
		if(fgets(szBuff, sizeof(szBuff), pfile) == NULL)
			break;

		if((pToken = strtok(szBuff, seperate)) == NULL)
			continue;

		if(strcmp(pToken, "kmsIP") == 0)
		{
			if((pToken = strtok(NULL, seperate)) == NULL)
				continue;
			strncpy(pContext->pConfig->kmsIP, pToken, sizeof(pContext->pConfig->kmsIP) -1);
			PRINT_DEBUG("kmsIP");
			PRINT_DEBUG(pContext->pConfig->kmsIP);
		}
		else if(strcmp(pToken, "kmsPort") == 0)
		{			
			if((pToken = strtok(NULL, seperate)) == NULL)
				continue;
			strncpy(pContext->pConfig->kmsPort, pToken, sizeof(pContext->pConfig->kmsPort) -1);
			PRINT_DEBUG("kmsPort");
			PRINT_DEBUG(pContext->pConfig->kmsPort);
		}
		else if(strcmp(pToken, "agentID") == 0)
		{
			if((pToken = strtok(NULL, seperate)) == NULL)
				continue;
			strncpy(pContext->pConfig->agentID, pToken, sizeof(pContext->pConfig->agentID) -1);
			PRINT_DEBUG("agentID");
			PRINT_DEBUG(pContext->pConfig->agentID);
		}
		else if(strcmp(pToken, "agentType") == 0)
		{
			if((pToken = strtok(NULL, seperate)) == NULL)
				continue;
			strncpy(pContext->pConfig->agentType, pToken, sizeof(pContext->pConfig->agentType) -1);
			PRINT_DEBUG("agentType");
			PRINT_DEBUG(pContext->pConfig->agentType);
		}
		else if(strcmp(pToken, "agentHint") == 0)
		{
			// strtok로 파싱할 경우 base64encode 문자열의 패딩문자'='가 유실될 수 있으므로 사용하지 않는다.
			unsigned int i = 0;
			int nAgentHintPtr = 0;
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
					pContext->pConfig->agentHint[nAgentHintPtr++] = pToken[i];
					bStartStr = 1;
				}
				else if(bStartStr == 1 && pToken[i] != ' ' && pToken[i] != '\t' && pToken[i] != '\r' && pToken[i] != '\n')
				{
					pContext->pConfig->agentHint[nAgentHintPtr++] = pToken[i];					
				}
			}
			PRINT_DEBUG("agentHint");
			PRINT_DEBUG(pContext->pConfig->agentHint);
		}
		else if(strcmp(pToken, "Integrity") == 0)
		{
			// strtok로 파싱할 경우 base64encode 문자열의 패딩문자'='가 유실될 수 있으므로 사용하지 않는다.
			unsigned int i = 0;
			int nIntegrityPtr = 0;
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
					pContext->pConfig->Integrity[nIntegrityPtr++] = pToken[i];
					bStartStr = 1;
				}
				else if(bStartStr == 1 && pToken[i] != ' ' && pToken[i] != '\t' && pToken[i] != '\r' && pToken[i] != '\n')
				{
					pContext->pConfig->Integrity[nIntegrityPtr++] = pToken[i];					
				}
			}
			PRINT_DEBUG("Integrity");
			PRINT_DEBUG(pContext->pConfig->Integrity);
		}
	}

error:

	if(pfile)
		fclose(pfile);

	PRINT_DEBUG("KM_SetConfig End.\n");

	return nRet;
}

int KM_VerifyAgentHint(Agent_Ctx *pContext)
{
	int nRet = 0;
	char *pszHash_B64 = NULL;
	UString usHash;	

#ifdef WIN32
	PIP_ADAPTER_INFO pAdapterInfo = NULL;
	IP_ADAPTER_INFO AdapterInfo[16];			// Allocate information for up to 16 NICs
	DWORD dwBufLen = sizeof(AdapterInfo);		// Save the memory size of buffer
#else
	struct ifconf ifc;
	struct ifreq ifr[10];
	int sd, ifc_num, i;
	struct in_addr addr; 
	char host[NI_MAXHOST] = {0};
#endif

	memset(&usHash, 0x00, sizeof(UString));

	// agentType이 1이면(=공용이면) AgentHint 체크를 하지 않고 IP에 0.0.0.0을 넣는다.
	if(strncmp(pContext->pConfig->agentType, "1", 1) == 0)
	{
		PRINT_DEBUG("agentType == 1");
		strncpy(pContext->pConfig->agentIP, "0.0.0.0", sizeof(pContext->pConfig->agentIP) -1);
		goto error;
	}

#ifdef WIN32
	PRINT_DEBUG("KM_VerifyAgentHint Start.");

	if((nRet = GetAdaptersInfo(AdapterInfo, &dwBufLen)) != TK_SUCCESS)
	{
		PRINT_DEBUG("*** GetAdaptersInfo error.");
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_VERIFYAGENTHINT_GETADAPTERSINFO;
		goto error;
	}

	pAdapterInfo = AdapterInfo;// Contains pointer to current adapter info

	do
	{	
		char *pIP = pAdapterInfo->IpAddressList.IpAddress.String;
		UString usIP;
		
		memset(&usHash, 0x00, sizeof(UString));

		if (!strcmp(pIP, "127.0.0.1"))
			continue;

		// SHA256(IP)
		usIP.value = pIP;
		usIP.length = strlen(pIP);
		if((nRet = TK_Sha256Hash(&usIP, &usHash)) != TK_SUCCESS)
			goto error;
		// B64Encode(SHA256(IP))
		if((nRet = TK_Base64_Encode(&usHash, &pszHash_B64)) != TK_SUCCESS)
			goto error;
		// Compare B64Encode(SHA256(IP)) with agentHint		
		PRINT_DEBUG("compare B64(sha256(IP)) with agentHint");
		PRINT_DEBUG(pszHash_B64);
		PRINT_DEBUG(pContext->pConfig->agentHint);
		PRINT_DEBUG(pIP);

		if(strncmp(pContext->pConfig->agentHint, pszHash_B64, strlen(pContext->pConfig->agentHint)) == 0)
		{
			// 확인 된 Client IP를 Config에 저장.			
			strncpy(pContext->pConfig->agentIP, pIP, sizeof(pContext->pConfig->agentIP) -1);
			PRINT_DEBUG("matched.");			
			break;
		}
		pAdapterInfo = pAdapterInfo->Next;		// Progress through linked list
		TK_MemFree((void**)&pszHash_B64);
		TK_Free_UString(&usHash);
	}
	while(pAdapterInfo);

	if(strlen(pContext->pConfig->agentIP) == 0)
	{
		// IP 획득 실패!!! Critical error!
		PRINT_DEBUG("*** IP Check Failed.");
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_VERIFYAGENTHINT_INVALIDIP;
		goto error;
	}

#else

#ifdef AIX
	#define SIOCGIFCONF CSIOCGIFCONF
	PRINT_DEBUG("AIX");
#endif
	
	PRINT_DEBUG("KM_VerifyAgentHint Start.");

	if((sd = socket(PF_INET, SOCK_DGRAM, 0)) == 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_VERIFYAGENTHINT_SOCKET;
		goto error;
	}

	ifc.ifc_len = sizeof(ifr);
	ifc.ifc_ifcu.ifcu_buf = (caddr_t)ifr;

	if (ioctl(sd, SIOCGIFCONF/*CSIOCGIFCONF*/, &ifc) != 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_VERIFYAGENTHINT_IOCTL;
		goto error;
	}

	ifc_num = ifc.ifc_len / sizeof(struct ifreq);

	for (i = 0; i < ifc_num; ++i)
	{		
		UString usIP;

		if (ifc.ifc_ifcu.ifcu_req[i].ifr_ifru.ifru_addr.sa_family != AF_INET) 
			continue;

		addr = ((struct sockaddr_in *)&ifc.ifc_ifcu.ifcu_req[i].ifr_ifru.ifru_addr)->sin_addr; 
		strcpy(host, inet_ntoa(addr));

		if (!strcmp(host, "127.0.0.1"))
			continue;

		PRINT_DEBUG(host);
		// SHA256(IP)
		usIP.value = host;
		usIP.length = strlen(host);
		if((nRet = TK_Sha256Hash(&usIP, &usHash)) != TK_SUCCESS)
			goto error;
		// B64Encode(SHA256(IP))
		if((nRet = TK_Base64_Encode(&usHash, &pszHash_B64)) != TK_SUCCESS)
		{
			nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_VERIFYAGENTHINT;
			goto error;
		}
		PRINT_DEBUG("compare B64(sha256(IP)) with agentHint");
		PRINT_DEBUG(pszHash_B64);
		PRINT_DEBUG(pContext->pConfig->agentHint);
		PRINT_DEBUG(host);

		if(strncmp(pContext->pConfig->agentHint, pszHash_B64, strlen(pContext->pConfig->agentHint)) == 0)
		{			
			// 확인 된 Client IP를 Config에 저장.
			strncpy(pContext->pConfig->agentIP, host, sizeof(pContext->pConfig->agentIP) -1);
			PRINT_DEBUG("matched.");
			break;
		}			
		TK_MemFree((void**)&pszHash_B64);
		TK_Free_UString(&usHash);
	}

	if(strlen(pContext->pConfig->agentIP) == 0)
	{
		// IP 획득 실패!!! Critical error!
		PRINT_DEBUG("*** IP Check Failed.");
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_VERIFYAGENTHINT_INVALIDIP;
		goto error;
	}
	close(sd);
#endif

error:

	TK_MemFree((void**)&pszHash_B64);
	TK_Free_UString(&usHash);
	PRINT_DEBUG("KM_VerifyAgentHint End.\n");

	return nRet;
}

int KM_VerifyIntegrity(Agent_Ctx *pContext)
{
	int nRet = 0;
	char IntegrityText[200] = {0};
	char *szHMACResult_B64 = NULL;
	UString HMACKey;
	UString HMACResult;

	memset(&HMACKey, 0x00, sizeof(UString));
	memset(&HMACResult, 0x00, sizeof(UString));
	
	PRINT_DEBUG("KM_VerifyIntegrity Start.");

	// HMAC 키 생성
	{
		UString agentIP;
		agentIP.value = pContext->pConfig->agentIP;
		agentIP.length = strlen(pContext->pConfig->agentIP);

		if((nRet = KM_Make_KeyFromMaterial(&agentIP, &HMACKey)) != TK_SUCCESS)
			goto error;
	}
	// HMAC 생성	
	{
		// Integrity(HMAC) 원본 메시지 생성
		UString HMACText;
		
		sprintf(IntegrityText, "%s%s%s%s%s",pContext->pConfig->kmsIP, pContext->pConfig->kmsPort, pContext->pConfig->agentID, pContext->pConfig->agentType, pContext->pConfig->agentHint);

		HMACText.value = IntegrityText;
		HMACText.length = strlen(IntegrityText);
		
		if((nRet = TK_Make_HMAC(SHA256, &HMACKey, &HMACText, &HMACResult)) != TK_SUCCESS)
			goto error;
	}

	
	// Base64Encode	
 	if((nRet = TK_Base64_Encode(&HMACResult, &szHMACResult_B64)) != TK_SUCCESS)
		goto error;
	PRINT_DEBUG("Compare HMAC with Integrity");
	PRINT_DEBUG(szHMACResult_B64);
	PRINT_DEBUG(pContext->pConfig->Integrity);

	// Integrity값과 HMAC값 비교	
	if(strncmp(pContext->pConfig->Integrity, szHMACResult_B64, sizeof(pContext->pConfig->Integrity)) != 0)
	{
		PRINT_DEBUG("Integrity Check Faild.");
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_VERIFYINTEGRITY_VERIFY;
		goto error;
	}	
	PRINT_DEBUG("Integrity Check Success.");

error:

	TK_Free_UString(&HMACKey);
	TK_Free_UString(&HMACResult);
	TK_MemFree((void**)&szHMACResult_B64);
	
	PRINT_DEBUG("KM_VerifyIntegrity End.\n");
	return nRet;
}

int KM_Make_Agent_HMAC(Agent_Ctx *pContext)
{
	int nRet = 0;
	UString hmacKey;
	UString agentHmac;
	char *szAgentHMAC_B64 = NULL;

	memset(&hmacKey, 0x00, sizeof(UString));
	memset(&agentHmac, 0x00, sizeof(UString));

	// HMAC 키 생성
	{
		UString agentIP;
		agentIP.value = pContext->pConfig->agentIP;
		agentIP.length = strlen(pContext->pConfig->agentIP);

		if((nRet = KM_Make_KeyFromMaterial(&agentIP, &hmacKey)) != TK_SUCCESS)
			goto error;
	}
	// HMAC 생성
	{
		UString agentID;
		agentID.value = pContext->pConfig->agentID;
		agentID.length = strlen(pContext->pConfig->agentID);

		if((nRet = TK_Make_HMAC(SHA256, &hmacKey, &agentID, &agentHmac)) != TK_SUCCESS)
			goto error;
	}
	// Base64Encode
	if((nRet = TK_Base64_Encode(&agentHmac, &szAgentHMAC_B64)) != TK_SUCCESS)
		goto error;

	memcpy(pContext->pConfig->agentHMAC, szAgentHMAC_B64, strlen(szAgentHMAC_B64));

	PRINT_DEBUG("Agent HMAC");
	PRINT_DEBUG(pContext->pConfig->agentHMAC);

error:

	TK_Free_UString(&hmacKey);
	TK_Free_UString(&agentHmac);
	TK_MemFree((void**)&szAgentHMAC_B64);

	return nRet;
}

int KM_Make_KeyFromMaterial(UString *pMaterial, UString *pKey)
{
	int nRet = 0;
	char sha256Val[SHA_256_LEN] = {0};

	if(pMaterial->value == NULL || pMaterial->length == 0 || pKey == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MAKE_KEYFROMMATERIAL_ARG_ERROR;
		goto error;
	}	

	if((nRet = TK_Sha256Hash(pMaterial, pKey)) != TK_SUCCESS)
		goto error;

	memcpy(sha256Val, pKey->value, sizeof(sha256Val));

	// SHA256(in) 을 4,1,3,2 순서로 쪼개어 키로 만든다.
	memcpy(&pKey->value[0],		&sha256Val[24],	8);
	memcpy(&pKey->value[8],		&sha256Val[0],	8);
	memcpy(&pKey->value[16],	&sha256Val[16],	8);
	memcpy(&pKey->value[24],	&sha256Val[8],	8);

error:

	return nRet;
}

int KM_Make_KEK_Material(Agent_Ctx *pContext)
{
	int		nRet = 0;
	char	randomNumber[32] = {0};

	if((nRet = TK_Make_Random(randomNumber, sizeof(randomNumber))) != TK_SUCCESS)
		goto error;

	memcpy(pContext->kekMaterial, randomNumber, sizeof(randomNumber));
	PRINT_DEBUG("KEK Material");	
	PRINT_DEBUG_BIN2STR(pContext->kekMaterial, sizeof(pContext->kekMaterial));

error:

	return nRet;
}

int KM_Make_KEK(Agent_Ctx *pContext, UString *pKek)
{
	int nRet = 0;
	UString kekMaterial;
	
	kekMaterial.value = pContext->kekMaterial;
	kekMaterial.length = sizeof(pContext->kekMaterial);

	if((nRet = KM_Make_KeyFromMaterial(&kekMaterial, pKek)) != TK_SUCCESS)
		goto error;

error:
	
	return nRet;
}

int KM_EncryptKey(Agent_Ctx *pContext, Key *pKey)
{
	int nRet = 0;
	UString kek;
	UString encKey;

	memset(&kek, 0x00, sizeof(UString));
	memset(&encKey, 0x00, sizeof(UString));

	PRINT_DEBUG("KM_EncryptKey Start.");

	// Make KEK
	if((nRet = KM_Make_KEK(pContext, &kek)) != TK_SUCCESS)
		goto error;
	// encrypt key
	{
		UString plainKey;
		plainKey.value = pKey->enc_key_value;
		plainKey.length = pKey->key_size;

		if((nRet = TK_Aes128_Encrypt(&encKey, &plainKey, &kek)) != TK_SUCCESS)
			goto error;
	}
	// Set Enc Key
	memset(pKey->enc_key_value, 0x00, sizeof(pKey->enc_key_value));
	memcpy(pKey->enc_key_value, encKey.value, encKey.length);
	pKey->key_size = encKey.length;

	PRINT_DEBUG("KM_EncryptKey Success.");

error:

	TK_Free_UString(&kek);
	TK_Free_UString(&encKey);

	PRINT_DEBUG("KM_EncryptKey End.\n");

	return nRet;
}

int KM_DecryptKey(Agent_Ctx *pContext, Key *pKey)
{
	int nRet = 0;
	UString kek;
	UString decKey;

	memset(&kek, 0x00, sizeof(UString));
	memset(&decKey, 0x00, sizeof(UString));

	// Make KEK
	if((nRet = KM_Make_KEK(pContext, &kek)) != TK_SUCCESS)
		goto error;
	// Decrypt key
	{
		UString encKey;
		encKey.value = pKey->enc_key_value;
		encKey.length = pKey->key_size;

		if((nRet = TK_Aes128_Decrypt(&decKey, &encKey, &kek)) != TK_SUCCESS)
			goto error;
	}

	// Set Dec Key
	memset(pKey->enc_key_value, 0x00, sizeof(pKey->enc_key_value));
	memcpy(pKey->enc_key_value, decKey.value, decKey.length);
	pKey->key_size = decKey.length;

error:
	TK_Free_UString(&kek);
	TK_Free_UString(&decKey);

	return nRet;
}

int KM_MakeKIR(char* I_ID, char* R_ID, UString usRandom2, UString *pusKIR)
{
	int nRet = 0;
	UString usHashI_ID, usHashR_ID, usResultXor;

	memset(&usHashI_ID, 0x00, sizeof(UString));
	memset(&usHashR_ID, 0x00, sizeof(UString));
	memset(&usResultXor, 0x00, sizeof(UString));

	{
		UString usI_ID, usR_ID;
		usI_ID.value = I_ID;
		usI_ID.length = strlen(I_ID);
		if((nRet = TK_Sha256Hash(&usI_ID, &usHashI_ID)) != TK_SUCCESS)
			goto error;

		usR_ID.value = R_ID;
		usR_ID.length = strlen(R_ID);
		if((nRet = TK_Sha256Hash(&usR_ID, &usHashR_ID)) != TK_SUCCESS)
			goto error;
	}	

	// Xor 계산 결과 버퍼
	if((nRet = TK_Set_UString(&usResultXor, NULL, IND_BLOCK_SIZE)) != TK_SUCCESS)
		goto error;

	KM_ComputeXOR_IND_BLOCK(g_IND_PREFIX, usHashI_ID.value, usResultXor.value);
	KM_ComputeXOR_IND_BLOCK(usResultXor.value, usRandom2.value, usResultXor.value);
	KM_ComputeXOR_IND_BLOCK(usResultXor.value, usHashR_ID.value, usResultXor.value);
	KM_ComputeXOR_IND_BLOCK(usResultXor.value, g_IND_POSTFIX, usResultXor.value);

	if((nRet = KM_Make_KeyFromMaterial(&usResultXor, pusKIR)) != TK_SUCCESS)
		goto error;

error:

	TK_Free_UString(&usHashI_ID);
	TK_Free_UString(&usHashR_ID);
	TK_Free_UString(&usResultXor);

	return nRet;
}

int KM_MakeSessionKey(UString usRandom1, UString usRandom2, UString usKIR, UString *pusSessionKey)
{
	int nRet = 0;
	UString usResultXor;

	memset(&usResultXor, 0x00, sizeof(UString));

	if((nRet = TK_Set_UString(&usResultXor, NULL, IND_BLOCK_SIZE)) != TK_SUCCESS)
		goto error;
	KM_ComputeXOR_IND_BLOCK(usRandom1.value, usRandom2.value, usResultXor.value);
	
	if((nRet = TK_Aes128_Encrypt(pusSessionKey, &usResultXor, &usKIR)) != TK_SUCCESS)
		goto error;

error:

	TK_Free_UString(&usResultXor);

	return nRet;
}

void KM_ComputeXOR_IND_BLOCK(char *a, char *b, char *r)
{
	int i = 0;

	for(i = 0; i < IND_BLOCK_SIZE; i++)
	{
		r[i] = a[i] ^ b[i];
	}	
}
