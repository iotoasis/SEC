// TrustKeystoreAgent.cpp : DLL 응용 프로그램을 위해 내보낸 함수를 정의합니다.
//
#include "TrustKeystoreAgent.h"
#include "KeyManager.h"

#ifndef INDIRECT_AGENT
//////////////////////////////////////////////////////////////////////////
// int TrustKeystore_Init(void **ppCtx, char * szConfPath)
// 설명 : Agent Context 초기화함수. SSL Initialize, Conf File Read, Client 검증, KEK Material 생성 등
// Input : void 포인터, Config 파일 경로
// Output : Agent Context
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int TrustKeystore_Init(void **ppCtx, char * szConfPath)
{
	int			nRet		= 0;
	Agent_Ctx	**ppContext	= (Agent_Ctx**) ppCtx;

 	if(*ppContext != NULL || szConfPath == NULL || strlen(szConfPath) < 1)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_TRUSTKEYSTORE_INIT_ARG_ERROR;
 		goto error;
	}
	
	// setting memories
	if((*ppContext				= (Agent_Ctx*)	TK_MemAlloc(sizeof(Agent_Ctx)))	== NULL)	{	nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;	goto error;	}
	if(((*ppContext)->pKeyList	= (KeyList*)	TK_MemAlloc(sizeof(KeyList)))	== NULL)	{	nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;	goto error;	}
	if(((*ppContext)->pConfig	= (Config*)		TK_MemAlloc(sizeof(Config)))	== NULL)	{	nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;	goto error;	}

	if((nRet = KM_SetConfig(*ppContext, szConfPath)) != TK_SUCCESS)
		goto error;

	if((nRet = KM_VerifyAgentHint(*ppContext)) != TK_SUCCESS)		
		goto error;

	if((nRet = KM_VerifyIntegrity(*ppContext)) != TK_SUCCESS)
		goto error;

	if((nRet = KM_Make_Agent_HMAC(*ppContext)) != TK_SUCCESS)
 		goto error;

	if((nRet = KM_Make_KEK_Material(*ppContext)) != TK_SUCCESS)
		goto error;

	if((nRet = KM_InitComm(*ppContext)) != TK_SUCCESS)
		goto error;
		
error:
	
	if(nRet != TK_SUCCESS)
		KM_CtxFree(ppContext);

	return nRet;
}
//////////////////////////////////////////////////////////////////////////
// int TrustKeystore_GetKey(void *pCtx, char* szKeyID, char** keyValue, int* keyLen)
// 설명 : Key 요청 함수. 키 아이디를 전달받아 키값과 길이 반환
// expose_yn이 Y인 키만 리턴
// Input : Agent Context, Key ID
// Output : Key Value, Key Length
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int TrustKeystore_GetKey(void *pCtx, char* szKeyID, char** keyValue, int* keyLen)
{
	int nRet = 0;
	Agent_Ctx *pContext = (Agent_Ctx*) pCtx;
	Key key;

	memset(&key, 0x00, sizeof(Key));

	if(szKeyID == NULL || strlen(szKeyID) < 1)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_TRUSTKEYSTORE_GETKEY_ARG_ERROR;
		goto error;
	}

	// context 체크
	if((nRet = KM_CheckCtx(pContext)) != TK_SUCCESS) goto error;

	// 복호화 된 키를 반환
	if((nRet = KM_GetKey(pContext, szKeyID, &key)) != TK_SUCCESS)
		goto error;

	// Key HMAC 체크
	if((nRet = KM_VerifyKeyHMAC(pContext, &key)) != TK_SUCCESS)
		goto error;

	// 유효기간 체크
	if((nRet = KM_VerifyKeyValidDate(pContext, &key)) != TK_SUCCESS)
		goto error;

	//expose_level 체크
	if((nRet = KM_VerifyKeyExposeLevel(pContext, &key, USE_KEY_OUT_OF_AGENT)) != TK_SUCCESS)
		goto error;

	// 키값 반환
	if((*keyValue = (char*) TK_MemAlloc(key.key_size)) == NULL)	{	nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;	goto error;	}

	memcpy(*keyValue, key.enc_key_value, key.key_size);
	*keyLen = key.key_size;

error:
	memset(&key, 0x00, sizeof(Key));

	return nRet;
}
//////////////////////////////////////////////////////////////////////////
// int TrustKeystore_GetKeyAlgo(void *pCtx, char* szKeyID, char** szKeyAlgo)
// 설명 : Key 요청 함수. 키 아이디를 전달받아 키 알고리즘 반환
// Input : Agent Context, Key ID
// Output : Key Algorythm
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int TrustKeystore_GetKeyAlgo(void *pCtx, char* szKeyID, char** szKeyAlgo)
{
	int nRet = 0;
	Key key;
	Agent_Ctx *pContext = (Agent_Ctx*) pCtx;

	memset(&key, 0x00, sizeof(Key));

	if(szKeyID == NULL || strlen(szKeyID) < 1)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_TRUSTKEYSTORE_GETKEYALGO_ARG_ERROR;
		goto error;
	}

	// context 체크
	if((nRet = KM_CheckCtx(pContext)) != TK_SUCCESS)
		goto error;
	if((nRet = KM_GetKey(pContext, szKeyID, &key)) != TK_SUCCESS)
		goto error;
	// Key HMAC 체크
	if((nRet = KM_VerifyKeyHMAC(pContext, &key)) != TK_SUCCESS)
		goto error;
	// 유효기간 체크
	if((nRet = KM_VerifyKeyValidDate(pContext, &key)) != TK_SUCCESS)
		goto error;
	//expose_level 체크
// 	if((nRet = KM_VerifyKeyExposeLevel(pContext, &key, USE_KEY_OUT_OF_AGENT)) != TK_SUCCESS)
// 		goto error;

	if((*szKeyAlgo = (char*) TK_MemAlloc(strlen(key.key_algo) + 1)) == NULL)	{	nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;	goto error;	}

	memcpy(*szKeyAlgo, key.key_algo, strlen(key.key_algo));	
	
error:

	memset(&key, 0x00, sizeof(Key));

	return nRet;
}
//////////////////////////////////////////////////////////////////////////
// int TrustKeystore_GetKeyOPMode(void *pCtx, char* szKeyID, char** szKeyOPMode)
// 설명 : Key 요청 함수. 키 아이디를 전달받아 키 운영모드 반환
// Input : Agent Context, Key ID
// Output : Key OPMode
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int TrustKeystore_GetKeyOPMode(void *pCtx, char* szKeyID, char** szKeyOPMode)
{
	int nRet = 0;
	Key key;
	Agent_Ctx *pContext = (Agent_Ctx*) pCtx;

	memset(&key, 0x00, sizeof(Key));

	if(szKeyID == NULL || strlen(szKeyID) < 1)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_TRUSTKEYSTORE_GETKEYOPMODE_ARG_ERROR;
		goto error;
	}

	if((nRet = KM_CheckCtx(pContext)) != TK_SUCCESS)
		goto error;

	if((nRet = KM_GetKey(pContext, szKeyID, &key)) != TK_SUCCESS)
		goto error;

	// Key HMAC 체크
	if((nRet = KM_VerifyKeyHMAC(pContext, &key)) != TK_SUCCESS)
		goto error;

	// 유효기간 체크
	if((nRet = KM_VerifyKeyValidDate(pContext, &key)) != TK_SUCCESS)
		goto error;

	//expose_level 체크
// 	if((nRet = KM_VerifyKeyExposeLevel(pContext, &key, USE_KEY_OUT_OF_AGENT)) != TK_SUCCESS)
// 		goto error;

	if((*szKeyOPMode = (char*) TK_MemAlloc(strlen(key.op_mode) + 1)) == NULL)	{	nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;	goto error;	}

	strncpy(*szKeyOPMode, key.op_mode, strlen(key.op_mode));

error:

	memset(&key, 0x00, sizeof(Key));

	return nRet;
}

//////////////////////////////////////////////////////////////////////////
// int TrustKeystore_GetKeyInfo(void *pCtx, char* szKeyID, char** szKeyInfo)
// 설명 : Key 요청 함수. 키 아이디를 전달받아 키 스트링 반환
// Input : Agent Context, Key ID
// Output : KeyInfo(KeyID+'|'+b64E(KeyValue)+'|'+KeyAlgo+'|'+OPMode)
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int TrustKeystore_GetKeyInfo(void *pCtx, char* szKeyID, char** szKeyInfo)
{
	int nRet = 0;
	Agent_Ctx *pContext = (Agent_Ctx*) pCtx;
	Key key;	
	char *szB64KeyValue = NULL;
	char szKeyInfoLen = 0;
	
	memset(&key, 0x00, sizeof(Key));

	if(szKeyID == NULL || strlen(szKeyID) < 1)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_TRUSTKEYSTORE_GETKEYINFO_ARG_ERROR;
		goto error;
	}

	if((nRet = KM_CheckCtx(pContext)) != TK_SUCCESS)
		goto error;
	if((nRet = KM_GetKey(pContext, szKeyID, &key)) != TK_SUCCESS)
		goto error;
	// Key HMAC 체크
	if((nRet = KM_VerifyKeyHMAC(pContext, &key)) != TK_SUCCESS)
		goto error;
	// 유효기간 체크
	if((nRet = KM_VerifyKeyValidDate(pContext, &key)) != TK_SUCCESS)
		goto error;
	//expose_level 체크
	if((nRet = KM_VerifyKeyExposeLevel(pContext, &key, USE_KEY_OUT_OF_AGENT)) != TK_SUCCESS)
		goto error;
	
	{
		UString keyValue;
		keyValue.value = key.enc_key_value;
		keyValue.length = key.key_size;

		if((nRet = TK_Base64_Encode(&keyValue, &szB64KeyValue)) != TK_SUCCESS)
			goto error;
	}

	szKeyInfoLen += strlen(key.key_id);
	szKeyInfoLen += strlen("|");
	szKeyInfoLen += strlen(szB64KeyValue);
	szKeyInfoLen += strlen("|");
	szKeyInfoLen += strlen(key.key_algo);
	szKeyInfoLen += strlen("|");
	szKeyInfoLen += strlen(key.op_mode);
	
	if((*szKeyInfo = (char*)TK_MemAlloc(szKeyInfoLen +1)) == NULL)	{	nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;	goto error;	}

	sprintf(*szKeyInfo, "%s|%s|%s|%s", key.key_id, szB64KeyValue, key.key_algo, key.op_mode);	

error:
	
	memset(&key, 0x00, sizeof(Key));
	TK_MemFree((void**)&szB64KeyValue);
	return nRet;
}
//////////////////////////////////////////////////////////////////////////
// int TrustKeystore_GetEncKey(void *pCtx, char* szKeyID, char* keyValue, int* keyLen)
// 설명 : [유넷툴킷전용]암호화 된 Key 요청 함수. 키 아이디를 전달받아 암호화된 키값과 길이 반환
// Input : Agent Context, Key ID
// Output : Key Value, Key Length
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int TrustKeystore_GetEncKey(void *pCtx, char* szKeyID, char** keyValue, int* keyLen)
{
	int nRet = 0;
	Agent_Ctx *pContext = (Agent_Ctx*) pCtx;
	Key key;
	UString usKek, usEncKey;

	memset(&key, 0x00, sizeof(Key));
	memset(&usKek, 0x00, sizeof(UString));
	memset(&usEncKey, 0x00, sizeof(UString));

	if(szKeyID == NULL || strlen(szKeyID) < 1)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_TRUSTKEYSTORE_GETENCKEY_ARG_ERROR;
		goto error;
	}

	if((nRet = KM_GetKey(pContext, szKeyID, &key)) != TK_SUCCESS)
		goto error;
	// Key HMAC 체크
	if((nRet = KM_VerifyKeyHMAC(pContext, &key)) != TK_SUCCESS)
		goto error;
	// 유효기간 체크
	if((nRet = KM_VerifyKeyValidDate(pContext, &key)) != TK_SUCCESS)
		goto error;
	// expose_level 체크
	if((nRet = KM_VerifyKeyExposeLevel(pContext, &key, USE_KEY_IN_AGENT)) != TK_SUCCESS)
		goto error;
	// Kek 생성 material: key_id
	{
		UString usKeyMaterial;
		usKeyMaterial.value = key.key_id;
		usKeyMaterial.length = strlen(key.key_id);
		if((nRet = KM_Make_KeyFromMaterial(&usKeyMaterial, &usKek)) != TK_SUCCESS)
			goto error;		
	}
	// Key 암호화
	{
		UString usKey;
		usKey.value = key.enc_key_value;
		usKey.length = key.key_size;
		if((nRet = TK_Aes128_Encrypt(&usEncKey, &usKey, &usKek)) != TK_SUCCESS)
			goto error;
	}

	if((*keyValue = (char*)TK_MemAlloc(usEncKey.length)) == NULL)	{	nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;	goto error;	}

	memcpy(*keyValue, usEncKey.value, usEncKey.length);
	*keyLen = usEncKey.length;

error:

	memset(&key, 0x00, sizeof(Key));
	TK_Free_UString(&usKek);
	TK_Free_UString(&usEncKey);

	return nRet;
}

//////////////////////////////////////////////////////////////////////////
// int TrustKeystore_GetEncKeyInfo(void *pCtx, char* szKeyID, char** szEncKeyInfo)
// 설명 : [유넷툴킷전용]암호화 된 Key 요청 함수. 키 아이디를 전달받아 암호화된 키값과 길이 반환
// Input : Agent Context, Key ID
// Output : KeyInfo(KeyID+'|'+b64E(EncKeyValue)+'|'+KeyAlgo+'|'+OPMode)
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int TrustKeystore_GetEncKeyInfo(void *pCtx, char* szKeyID, char** szEncKeyInfo)
{
	int nRet = 0;
	Agent_Ctx *pContext = (Agent_Ctx*) pCtx;
	Key key;	
	UString usKek, usEncKey;
	char *szB64KeyValue = NULL;
	char szKeyInfoLen = 0;

	memset(&key, 0x00, sizeof(Key));
	memset(&usKek, 0x00, sizeof(UString));
	memset(&usEncKey, 0x00, sizeof(UString));

	if(szKeyID == NULL || strlen(szKeyID) < 1)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_TRUSTKEYSTORE_GETENCKEYINFO_ARG_ERROR;
		goto error;
	}

	if((nRet = KM_CheckCtx(pContext)) != TK_SUCCESS)
		goto error;
	if((nRet = KM_GetKey(pContext, szKeyID, &key)) != TK_SUCCESS)
		goto error;
	// Key HMAC 체크
	if((nRet = KM_VerifyKeyHMAC(pContext, &key)) != TK_SUCCESS)
		goto error;
	// 유효기간 체크
	if((nRet = KM_VerifyKeyValidDate(pContext, &key)) != TK_SUCCESS)
		goto error;
	//expose_level 체크
	if((nRet = KM_VerifyKeyExposeLevel(pContext, &key, USE_KEY_IN_AGENT)) != TK_SUCCESS)
		goto error;

	// Kek 생성 material: key_id
	{
		UString usKeyMaterial;
		usKeyMaterial.value = key.key_id;
		usKeyMaterial.length = strlen(key.key_id);
		if((nRet = KM_Make_KeyFromMaterial(&usKeyMaterial, &usKek)) != TK_SUCCESS)
			goto error;		
	}
	// Key 암호화
	{
		UString usKey;
		usKey.value = key.enc_key_value;
		usKey.length = key.key_size;
		if((nRet = TK_Aes128_Encrypt(&usEncKey, &usKey, &usKek)) != TK_SUCCESS)
			goto error;
	}

	if((nRet = TK_Base64_Encode(&usEncKey, &szB64KeyValue)) != TK_SUCCESS)
		goto error;

	szKeyInfoLen += strlen(key.key_id);
	szKeyInfoLen += strlen("|");
	szKeyInfoLen += strlen(szB64KeyValue);
	szKeyInfoLen += strlen("|");
	szKeyInfoLen += strlen(key.key_algo);
	szKeyInfoLen += strlen("|");
	szKeyInfoLen += strlen(key.op_mode);

	if((*szEncKeyInfo = (char*)TK_MemAlloc(szKeyInfoLen +1)) == NULL)	{	nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;	goto error;	}

	sprintf(*szEncKeyInfo, "%s|%s|%s|%s", key.key_id, szB64KeyValue, key.key_algo, key.op_mode);	

error:
	
	memset(&key, 0x00, sizeof(Key));
	TK_Free_UString(&usKek);
	TK_Free_UString(&usEncKey);
	TK_MemFree((void**)&szB64KeyValue);

	return nRet;
}

//////////////////////////////////////////////////////////////////////////
// int TrustKeystore_UpdateKey(void *pCtx, char* szKeyIDList)
// 설명 : Key Update 함수. 키 아이디를 '|'로 연접한 리스트를 전달 받아 해당 키 갱신.
// 인자가 null일 경우 Agent에 보유중인 모든 키에대해 갱신 수행
// Input : Agent Context, Key ID List
// Output :
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int TrustKeystore_UpdateKey(void *pCtx, char* szKeyIDList)
{
	int nRet = 0;
	Agent_Ctx *pContext = (Agent_Ctx*) pCtx;
	char *szUpdateAvailableKeyIDList = NULL;
	KeyList keyList;

	memset(&keyList, 0x00, sizeof(KeyList));

	if((nRet = KM_CheckCtx(pContext)) != TK_SUCCESS)
		goto error;
	if((nRet = KM_GetUpdateAvailableKeyIDList(pContext, szKeyIDList, &szUpdateAvailableKeyIDList)) != TK_SUCCESS)
		goto error;
	if((nRet = KM_GetKeyListFromKMS(pContext, szUpdateAvailableKeyIDList, &keyList)) != TK_SUCCESS)
		goto error;
	if((nRet = KM_SetKeyListIntoMemory(pContext, &keyList)) != TK_SUCCESS)
		goto error;

error:
	TK_MemFree((void**)&szUpdateAvailableKeyIDList);
	TK_MemFree((void**)&keyList.pKey);

	return nRet;
}
//////////////////////////////////////////////////////////////////////////
// int TrustKeystore_Encrypt(void *pCtx, char* szKeyID, char* in, int inLen, char **ppOut, int* outLen)
// 설명 : 키 아이디, 평문값을 전달받아 KMS에서 암호화 한 결과를 리턴.
// Input : Agent Context, Key ID, in, inLen
// Output : out, outLen
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int TrustKeystore_Encrypt(void *pCtx, char* szKeyID, char* in, int inLen, char **ppOut, int* outLen)
{
	int nRet = 0;
	Agent_Ctx *pContext = (Agent_Ctx*) pCtx;
	char *pszB64PlainText = NULL;
	char *pszArg = NULL;
	char *pReqMsg = NULL;
	char *pResMsg = NULL;
	OP_RESPONSE response;
	UString usDecText;

	memset(&response, 0x00, sizeof(OP_RESPONSE));
	memset(&usDecText, 0x00, sizeof(UString));

	if((nRet = KM_CheckCtx(pContext)) != TK_SUCCESS)
		goto error;

	if(szKeyID == NULL || strlen(szKeyID) <= 0 || in == NULL || inLen == 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_TRUSTKEYSTORE_ENCRYPT_ARG_ERROR;
		goto error;
	}

	{
		UString usPlainText;
		usPlainText.value = in;
		usPlainText.length = inLen;

		if((nRet = TK_Base64_Encode(&usPlainText, &pszB64PlainText)) != TK_SUCCESS)
			goto error;
	}

	if((pszArg = (char*) TK_MemAlloc(strlen(szKeyID) + strlen("|") + strlen(pszB64PlainText) + 1)) == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
		goto error;
	}
	
	sprintf(pszArg, "%s|%s", szKeyID, pszB64PlainText);

	if((nRet = KM_MakeRequest(pContext, OP_REQUEST_ENCRYPT, pszArg, &pReqMsg)) != TK_SUCCESS)
		goto error;
	if((nRet = KM_RequestToKMS(pContext, pReqMsg, &pResMsg)) != TK_SUCCESS)
		goto error;
	if((nRet = TK_ParseResponse(pResMsg, &response)) != TK_SUCCESS)
		goto error;		
	if((nRet = TK_Base64_Decode(response.pszText, &usDecText)) != TK_SUCCESS)
		goto error;

	if((*ppOut = (char*)TK_MemAlloc(usDecText.length)) == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
		goto error;
	}
	memcpy(*ppOut, usDecText.value, usDecText.length);
	*outLen = usDecText.length;

error:

	TK_MemFree((void**)&pszB64PlainText);
	TK_MemFree((void**)&pszArg);
	TK_MemFree((void**)&pReqMsg);
	TK_MemFree((void**)&pResMsg);
	TK_MemFree((void**)&response.pszText);	
	TK_Free_UString(&usDecText);

	return nRet;
}
//////////////////////////////////////////////////////////////////////////
// int TrustKeystore_Decrypt(void *pCtx, char* szKeyID, char* in, int inLen, char **ppOut, int* outLen)
// 설명 : 키 아이디, 암호문을 전달받아 KMS에서 복호화 한 결과를 리턴.
// Input : Agent Context, Key ID, in, inLen
// Output : out, outLen
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
int TrustKeystore_Decrypt(void *pCtx, char* szKeyID, char* in, int inLen, char **ppOut, int* outLen)
{
	int nRet = 0;
	Agent_Ctx *pContext = (Agent_Ctx*) pCtx;
	char *pszB64EncText = NULL;
	char *pszArg = NULL;
	char *pReqMsg = NULL;
	char *pResMsg = NULL;
	OP_RESPONSE response;
	UString usDecText;

	memset(&response, 0x00, sizeof(OP_RESPONSE));
	memset(&usDecText, 0x00, sizeof(UString));

	if((nRet = KM_CheckCtx(pContext)) != TK_SUCCESS)
		goto error;

	if(szKeyID == NULL || strlen(szKeyID) <= 0 || in == NULL || inLen == 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_TRUSTKEYSTORE_DECRYPT_ARG_ERROR;
		goto error;
	}


	{
		UString usEncText;
		usEncText.value = in;
		usEncText.length = inLen;

		if((nRet = TK_Base64_Encode(&usEncText, &pszB64EncText)) != TK_SUCCESS)
			goto error;
	}

	if((pszArg = (char*) TK_MemAlloc(strlen(szKeyID) + strlen("|") + strlen(pszB64EncText) + 1)) == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
		goto error;
	}

	sprintf(pszArg, "%s|%s", szKeyID, pszB64EncText);

	if((nRet = KM_MakeRequest(pContext, OP_REQUEST_DECRYPT, pszArg, &pReqMsg)) != TK_SUCCESS)
		goto error;
	if((nRet = KM_RequestToKMS(pContext, pReqMsg, &pResMsg)) != TK_SUCCESS)
		goto error;
	if((nRet = TK_ParseResponse(pResMsg, &response)) != TK_SUCCESS)
		goto error;
	if((nRet = TK_Base64_Decode(response.pszText, &usDecText)) != TK_SUCCESS)
		goto error;

	if((*ppOut = (char*)TK_MemAlloc(usDecText.length)) == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
		goto error;
	}
	memcpy(*ppOut, usDecText.value, usDecText.length);
	*outLen = usDecText.length;

error:

	TK_MemFree((void**)&pszB64EncText);
	TK_MemFree((void**)&pszArg);
	TK_MemFree((void**)&pReqMsg);
	TK_MemFree((void**)&pResMsg);
	TK_MemFree((void**)&response.pszText);	
	TK_Free_UString(&usDecText);

	return nRet;
}

//////////////////////////////////////////////////////////////////////////
// int TrustKeystore_GetErrorCode(void *pCtx)
// 설명 : 직전 명령 실행에 대한 에러코드 반환 함수. 성공인 경우 0 리턴
// 실패인 경우 에러코드 리턴
// Input : Agent Context
// Output :
// Return : int 에러코드
//////////////////////////////////////////////////////////////////////////
int TrustKeystore_GetErrorCode()
{
	return g_nAgentErrorCode;
}
//////////////////////////////////////////////////////////////////////////
// char* TrustKeystore_GetErrorStr(void *pCtx)
// 설명 : 직전 명령 실행에 대한 에러메시지 반환 함수. 성공인 경우 성공 리턴
// 실패인 경우 에러메시지 리턴
// Input : Agent Context
// Output :
// Return : char* 에러메시지
//////////////////////////////////////////////////////////////////////////

char* TrustKeystore_GetErrorStr(int nErrorCode)
{
	if(nErrorCode <= -5000 && nErrorCode > -6000) // Agent error
	{
		int nErrorCount = sizeof(g_errorString)/sizeof(errorString);
		int i;
		for(i = 0; i < nErrorCount; i++)
		{
			if(g_errorString[i].nErrorCode == nErrorCode)
			{
				return g_errorString[i].szErrorStr;
			}
		}		
	}
	else if(nErrorCode <= -1000 && nErrorCode > -2000)	// Server error
	{
		return g_szAgentErrorMsg;
	}
	
	return "";
}

//////////////////////////////////////////////////////////////////////////
// int TrustKeystore_Final(void **ppCtx)
// 설명 : Agent 종료 함수. Agent Context 메모리 해제
// Input : Agent Context
// Output : Agent Context
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
void TrustKeystore_Final(void **ppCtx)
{
	KM_CtxFree((Agent_Ctx**)ppCtx);
}

int TrustKeystore_Indirect_MakeResponseKeyMsg(void *pCtx, char* szDeviceID, char *RequestMsg, int RequestLen, char **ResponseMsg, int* ResponseLen)
{
	int nRet = 0;
	Agent_Ctx *pContext = (Agent_Ctx*) pCtx;
	UString usR_ID, usReqRandom, usReqKeyID, usKIR, usSessionKey, usE_KIR, usE_SK;
	UString usTLV_I_ID, usTLV_E_KIR, usTLV_E_SK, usTLV_KeyAlgo, usTLV_KeyOPMode;
	char randomNumber[IND_BLOCK_SIZE * 2] = {0};	// buffer for r1||r2
	char *I_ID = szDeviceID;
	Key key;

	memset(&usR_ID, 0x00, sizeof(UString));
	memset(&usReqRandom, 0x00, sizeof(UString));
	memset(&usReqKeyID, 0x00, sizeof(UString));
	memset(&usKIR, 0x00, sizeof(UString));
	memset(&usSessionKey, 0x00, sizeof(UString));
	memset(&usE_KIR, 0x00, sizeof(UString));
	memset(&usE_SK, 0x00, sizeof(UString));
	memset(&usTLV_KeyAlgo, 0x00, sizeof(UString));
	memset(&usTLV_KeyOPMode, 0x00, sizeof(UString));

	memset(&usTLV_I_ID, 0x00, sizeof(UString));
	memset(&usTLV_E_KIR, 0x00, sizeof(UString));
	memset(&usTLV_E_SK, 0x00, sizeof(UString));	
	memset(&key, 0x00, sizeof(Key));

	if(szDeviceID == NULL || strlen(szDeviceID) <= 0 || RequestMsg == NULL || RequestLen == 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_TRUSTKEYSTORE_IND_RESPONSE_ARG_ERROR;
		goto error;
	}

	// context 체크
	if((nRet = KM_CheckCtx(pContext)) != TK_SUCCESS)
		goto error;
	if((nRet = TK_Indirect_PaseTLV(IND_TAG_DEVICEID, RequestMsg, RequestLen, &usR_ID)) != TK_SUCCESS)
		goto error;
	if((nRet = TK_Indirect_PaseTLV(IND_TAG_RANDOM, RequestMsg, RequestLen, &usReqRandom)) != TK_SUCCESS)
		goto error;
	if((nRet = TK_Indirect_PaseTLV(IND_TAG_KEYID, RequestMsg, RequestLen, &usReqKeyID)) != TK_SUCCESS)
		goto error;

	// 복호화 된 키를 반환
	if((nRet = KM_GetKey(pContext, usReqKeyID.value, &key)) != TK_SUCCESS)
		goto getkeyerror;
	// Key HMAC 체크
	if((nRet = KM_VerifyKeyHMAC(pContext, &key)) != TK_SUCCESS)
		goto getkeyerror;
	// 유효기간 체크
	if((nRet = KM_VerifyKeyValidDate(pContext, &key)) != TK_SUCCESS)
		goto getkeyerror;
	//expose_level 체크
// 	if((nRet = KM_VerifyKeyExposeLevel(pContext, &key, USE_KEY_OUT_OF_AGENT)) != TK_SUCCESS)
// 		goto getkeyerror;
	// check Dynamic key
	if(strncmp(key.key_Type, "D", sizeof(key.key_Type)) == 0)
	{
		nRet = TK_AGENT_ERROR_FAILED_INDIRECT_MAKERESPONSEKEYMSG_DYNAMIC;
		goto getkeyerror;
	}

	//////////////////////////////////////////////////////////////////////////


	// Random (r1)
	if((nRet = TK_Make_Random(randomNumber, IND_BLOCK_SIZE)) != TK_SUCCESS)
		goto error;

	// r1||r2
	memcpy(&randomNumber[IND_BLOCK_SIZE], usReqRandom.value, usReqRandom.length);

	// make KIR
	if((nRet = KM_MakeKIR(I_ID, usR_ID.value, usReqRandom, &usKIR)) != TK_SUCCESS)
		goto error;
	PRINT_DEBUG_BIN2STR(usKIR.value, usKIR.length);

	// E_KIR(r1||r2)
	{
		UString usR1R2;
		usR1R2.value = randomNumber;
		usR1R2.length = sizeof(randomNumber);
		if((nRet = TK_Aes128_Encrypt(&usE_KIR, &usR1R2, &usKIR)) != TK_SUCCESS)
			goto error;
	}	

	// SK(SessionKey)
	{
		UString usRandom1;
		usRandom1.value = randomNumber;
		usRandom1.length = IND_BLOCK_SIZE;
		if((nRet = KM_MakeSessionKey(usRandom1, usReqRandom, usKIR, &usSessionKey)) != TK_SUCCESS)
			goto error;
	}

	// E_SK(KEY_KeyID)
	{
		UString usKey;
		usKey.value = key.enc_key_value;
		usKey.length = key.key_size;
		if((nRet = TK_Aes128_Encrypt(&usE_SK, &usKey, &usSessionKey)) != TK_SUCCESS)
			goto error;
	}

	// Message 생성
	if((nRet = TK_Indirect_MakeTLV(IND_TAG_DEVICEID, I_ID, strlen(I_ID), &usTLV_I_ID)) != TK_SUCCESS)
		goto error;
	if((nRet = TK_Indirect_MakeTLV(IND_TAG_ENCRANDOM, usE_KIR.value, usE_KIR.length, &usTLV_E_KIR)) != TK_SUCCESS)
		goto error;
	if((nRet = TK_Indirect_MakeTLV(IND_TAG_ENCKEY, usE_SK.value, usE_SK.length, &usTLV_E_SK)) != TK_SUCCESS)
		goto error;
	if((nRet = TK_Indirect_MakeTLV(IND_TAG_KEYALGO, key.key_algo, strlen(key.key_algo), &usTLV_KeyAlgo)) != TK_SUCCESS)
		goto error;
	if((nRet = TK_Indirect_MakeTLV(IND_TAG_KEYOPMODE, key.op_mode, strlen(key.op_mode), &usTLV_KeyOPMode)) != TK_SUCCESS)
		goto error;

	if((*ResponseMsg = (char*)TK_MemAlloc(usTLV_I_ID.length + usTLV_E_KIR.length + usTLV_E_SK.length + usTLV_KeyAlgo.length + usTLV_KeyOPMode.length)) == NULL)
		goto error;

	memcpy(&(*ResponseMsg)[0], usTLV_I_ID.value, usTLV_I_ID.length);
	*ResponseLen = usTLV_I_ID.length;
	memcpy(&(*ResponseMsg)[*ResponseLen], usTLV_E_KIR.value, usTLV_E_KIR.length);
	*ResponseLen += usTLV_E_KIR.length;
	memcpy(&(*ResponseMsg)[*ResponseLen], usTLV_E_SK.value, usTLV_E_SK.length);
	*ResponseLen += usTLV_E_SK.length;
	memcpy(&(*ResponseMsg)[*ResponseLen], usTLV_KeyAlgo.value, usTLV_KeyAlgo.length);
	*ResponseLen += usTLV_KeyAlgo.length;
	memcpy(&(*ResponseMsg)[*ResponseLen], usTLV_KeyOPMode.value, usTLV_KeyOPMode.length);
	*ResponseLen += usTLV_KeyOPMode.length;

error:

	memset(&key, 0x00, sizeof(Key));

	TK_Free_UString(&usR_ID);
	TK_Free_UString(&usReqRandom);
	TK_Free_UString(&usReqKeyID);
	TK_Free_UString(&usKIR);
	TK_Free_UString(&usSessionKey);
	TK_Free_UString(&usE_KIR);
	TK_Free_UString(&usE_SK);
	TK_Free_UString(&usTLV_KeyAlgo);
	TK_Free_UString(&usTLV_KeyOPMode);

	TK_Free_UString(&usTLV_I_ID);
	TK_Free_UString(&usTLV_E_KIR);
	TK_Free_UString(&usTLV_E_SK);

	return nRet;

getkeyerror:

	// 키를 가져오다가 에러가 나면 에러코드를 메세지로 리턴한다.
	{
		char szErrorcode[5 + 1] = {0};
		UString usErrorcode;

		memset(&usErrorcode, 0x00, sizeof(UString));

		sprintf(szErrorcode, "%d", nRet);
		// Message 생성
		if((nRet = TK_Indirect_MakeTLV(IND_TAG_ERRORCODE, szErrorcode, strlen(szErrorcode), &usErrorcode)) != TK_SUCCESS)
			goto error;

		if((*ResponseMsg = (char*)TK_MemAlloc(usErrorcode.length)) == NULL)
			goto error;
		memcpy(*ResponseMsg, usErrorcode.value, usErrorcode.length);
		*ResponseLen = usErrorcode.length;

		TK_Free_UString(&usErrorcode);		
		nRet = TK_SUCCESS;
		goto error;
	}
}
#endif

#ifndef DIRECT_AGENT
int TrustKeystore_Indirect_Init(void **ppCtx)
{
	int			nRet		= 0;
	Agent_Ctx	**ppContext	= (Agent_Ctx**) ppCtx;

	if(*ppContext != NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_TRUSTKEYSTORE_IND_INIT_ARG_ERROR;
		goto error;
	}

	// setting memories
	if((*ppContext				= (Agent_Ctx*)	TK_MemAlloc(sizeof(Agent_Ctx)))	== NULL)	{	nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;	goto error;	}
	if(((*ppContext)->pKeyList	= (KeyList*)	TK_MemAlloc(sizeof(KeyList)))	== NULL)	{	nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;	goto error;	}
	if(((*ppContext)->pConfig	= (Config*)		TK_MemAlloc(sizeof(Config)))	== NULL)	{	nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;	goto error;	}

	if((nRet = KM_Make_KEK_Material(*ppContext)) != TK_SUCCESS)
		goto error;

error:

	if(nRet != TK_SUCCESS)
		KM_CtxFree(ppContext);

	return nRet;
}

int TrustKeystore_Indirect_GetKey(void *pCtx, char* szKeyID, char **keyValue, int* keyLen)
{
	int nRet = 0;
	Agent_Ctx *pContext = (Agent_Ctx*) pCtx;
	Key key;

	memset(&key, 0x00, sizeof(Key));

	if(szKeyID == NULL || strlen(szKeyID) <= 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_TRUSTKEYSTORE_IND_GETKEY_ARG_ERROR;
		goto error;
	}

	// context 체크
	if((nRet = KM_CheckCtx(pContext)) != TK_SUCCESS)
		goto error;
	// 메모리의 키를 복호화 해서 반환
	if((nRet = KM_GetKeyFromMemory(pContext, szKeyID, &key)) != TK_SUCCESS)
		goto error;
	// 키값 반환
	if((*keyValue = (char*) TK_MemAlloc(key.key_size)) == NULL)	{	nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;	goto error;	}

	memcpy(*keyValue, key.enc_key_value, key.key_size);
	*keyLen = key.key_size;

error:
	memset(&key, 0x00, sizeof(Key));
	return nRet;
}

int TrustKeystore_Indirect_GetKeyAlgo(void *pCtx, char* szKeyID, char **szKeyAlgo)
{
	int nRet = 0;
	Key key;
	Agent_Ctx *pContext = (Agent_Ctx*) pCtx;

	memset(&key, 0x00, sizeof(Key));

	if(szKeyID == NULL || strlen(szKeyID) <= 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_TRUSTKEYSTORE_IND_GETKEYALGO_ARG_ERROR;
		goto error;
	}

	// context 체크
	if((nRet = KM_CheckCtx(pContext)) != TK_SUCCESS)
		goto error;
	if((nRet = KM_GetKeyFromMemory(pContext, szKeyID, &key)) != TK_SUCCESS)
		goto error;

	if((*szKeyAlgo = (char*) TK_MemAlloc(strlen(key.key_algo) + 1)) == NULL)	{	nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;	goto error;	}

	memcpy(*szKeyAlgo, key.key_algo, strlen(key.key_algo));	

error:

	memset(&key, 0x00, sizeof(Key));

	return nRet;
}

int TrustKeystore_Indirect_GetKeyOPMode(void *pCtx, char* szKeyID, char **szKeyOPMode)
{
	int nRet = 0;
	Key key;
	Agent_Ctx *pContext = (Agent_Ctx*) pCtx;

	memset(&key, 0x00, sizeof(Key));

	if(szKeyID == NULL || strlen(szKeyID) <= 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_TRUSTKEYSTORE_IND_GETKEYOPMODE_ARG_ERROR;
		goto error;
	}

	if((nRet = KM_CheckCtx(pContext)) != TK_SUCCESS)
		goto error;

	if((nRet = KM_GetKeyFromMemory(pContext, szKeyID, &key)) != TK_SUCCESS)
		goto error;

	if((*szKeyOPMode = (char*) TK_MemAlloc(strlen(key.op_mode) + 1)) == NULL)	{	nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;	goto error;	}

	strncpy(*szKeyOPMode, key.op_mode, strlen(key.op_mode));

error:

	memset(&key, 0x00, sizeof(Key));

	return nRet;
}

int TrustKeystore_Indirect_MakeRequestKeyMsg(void *pCtx, char* szDeviceID, char* szKeyID, char **RequestMsg, int* RequestLen)
{
	int nRet = 0;
	Agent_Ctx *pContext = (Agent_Ctx*) pCtx;
	char r2[IND_BLOCK_SIZE] = {0};
	char *R_ID = szDeviceID;
	UString usTLV_DeviceID, usTLV_Random, usTLV_KeyID;	

	memset(&usTLV_DeviceID, 0x00, sizeof(UString));
	memset(&usTLV_Random, 0x00, sizeof(UString));
	memset(&usTLV_KeyID, 0x00, sizeof(UString));

	if(szDeviceID == NULL || strlen(szDeviceID) <= 0 || szKeyID == NULL || strlen(szKeyID) <= 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_TRUSTKEYSTORE_IND_REQUEST_ARG_ERROR;
		goto error;
	}

	// context 체크
	if((nRet = KM_CheckCtx(pContext)) != TK_SUCCESS)
		goto error;	
	// Device ID
	if((nRet = TK_Indirect_MakeTLV(IND_TAG_DEVICEID, R_ID, strlen(R_ID), &usTLV_DeviceID)) != TK_SUCCESS)
		goto error;
	memcpy(pContext->indirectionInfo.R_ID, R_ID, strlen(R_ID));
	// Random (r2)
	if((nRet = TK_Make_Random(r2, sizeof(r2))) != TK_SUCCESS)
		goto error;
	memcpy(pContext->indirectionInfo.r2, r2, sizeof(r2));

	if((nRet = TK_Indirect_MakeTLV(IND_TAG_RANDOM, r2, sizeof(r2), &usTLV_Random)) != TK_SUCCESS)
		goto error;
	// Key ID
	if((nRet = TK_Indirect_MakeTLV(IND_TAG_KEYID, szKeyID, strlen(szKeyID), &usTLV_KeyID)) != TK_SUCCESS)
		goto error;
	memcpy(pContext->indirectionInfo.key_id, szKeyID, strlen(szKeyID));
	
	// 전체 길이 계산
	*RequestLen = usTLV_DeviceID.length + usTLV_Random.length + usTLV_KeyID.length;
	*RequestMsg = (char*)TK_MemAlloc(*RequestLen);
	if(*RequestMsg == NULL)
	{
		nRet = -1;
		goto error;
	}
	memcpy(&(*RequestMsg)[0], usTLV_DeviceID.value, usTLV_DeviceID.length);
	memcpy(&(*RequestMsg)[usTLV_DeviceID.length], usTLV_Random.value, usTLV_Random.length);
	memcpy(&(*RequestMsg)[usTLV_DeviceID.length + usTLV_Random.length], usTLV_KeyID.value, usTLV_KeyID.length);	

error:

	TK_Free_UString(&usTLV_DeviceID);
	TK_Free_UString(&usTLV_Random);
	TK_Free_UString(&usTLV_KeyID);
	return nRet;
}

int TrustKeystore_Indirect_SetKey(void *pCtx,char *ResponseMsg, int ResponseLen)
{
	int nRet = 0;
	Agent_Ctx *pContext = (Agent_Ctx*) pCtx;
	UString usI_ID;			// Host(Gateway) Device ID
	UString usE_KIR;		// E_KIR(r1||r2)
	UString usE_SK;			// E_SK(KEY_keyid)
	UString usKeyAlgo;
	UString usKeyOPMode;
	UString usKIR;			
	UString usR1R2;			// r1||r2
	UString usSessionKey;	// SK
	UString usKey;
	UString usErrorcode;	// errorcode
	Key key;

	memset(&usI_ID, 0x00, sizeof(UString));
	memset(&usE_KIR, 0x00, sizeof(UString));
	memset(&usE_SK, 0x00, sizeof(UString));
	memset(&usKeyAlgo, 0x00, sizeof(UString));
	memset(&usKeyOPMode, 0x00, sizeof(UString));
	memset(&usKIR, 0x00, sizeof(UString));
	memset(&usR1R2, 0x00, sizeof(UString));
	memset(&usSessionKey, 0x00, sizeof(UString));
	memset(&usKey, 0x00, sizeof(UString));
	memset(&usErrorcode, 0x00, sizeof(UString));
	memset(&key, 0x00, sizeof(Key));	

	if(ResponseMsg == NULL || ResponseLen <= 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_TRUSTKEYSTORE_IND_SETKEY_ARG_ERROR;
		goto error;
	}

	// context 체크
	if((nRet = KM_CheckCtx(pContext)) != TK_SUCCESS)
		goto error;

	// error 체크
	if(TK_Indirect_PaseTLV(IND_TAG_ERRORCODE, ResponseMsg, ResponseLen, &usErrorcode) == TK_SUCCESS)
	{
		nRet = g_nAgentErrorCode = strtol(usErrorcode.value, NULL, 10);
		goto error;
	}
	
	// Get I_ID
	if((nRet = TK_Indirect_PaseTLV(IND_TAG_DEVICEID, ResponseMsg, ResponseLen, &usI_ID)) != TK_SUCCESS)
		goto error;
	// Get E_KIR
	if((nRet = TK_Indirect_PaseTLV(IND_TAG_ENCRANDOM, ResponseMsg, ResponseLen, &usE_KIR)) != TK_SUCCESS)
		goto error;
	// Get E_SK
	if((nRet = TK_Indirect_PaseTLV(IND_TAG_ENCKEY, ResponseMsg, ResponseLen, &usE_SK)) != TK_SUCCESS)
		goto error;
	// Get Keyalgo
	if((nRet = TK_Indirect_PaseTLV(IND_TAG_KEYALGO, ResponseMsg, ResponseLen, &usKeyAlgo)) != TK_SUCCESS)
		goto error;
	// Get KeyOPMode
	if((nRet = TK_Indirect_PaseTLV(IND_TAG_KEYOPMODE, ResponseMsg, ResponseLen, &usKeyOPMode)) != TK_SUCCESS)
		goto error;

	// Make KIR
	{
		UString usR2;

		usR2.value = pContext->indirectionInfo.r2;
		usR2.length = sizeof(pContext->indirectionInfo.r2);
		if((nRet = KM_MakeKIR(usI_ID.value, pContext->indirectionInfo.R_ID, usR2, &usKIR)) != TK_SUCCESS)
			goto error;
		PRINT_DEBUG_BIN2STR(usKIR.value, usKIR.length);
	}	

	// D_KIR(usE_KIR) == r1||r2
	if((nRet = TK_Aes128_Decrypt(&usR1R2, &usE_KIR, &usKIR)) != TK_SUCCESS)
		goto error;

	// Make SessionKey
	{
		UString usR1;
		UString usR2;

		usR1.value = usR1R2.value;
		usR1.length = IND_BLOCK_SIZE;
		usR2.value = pContext->indirectionInfo.r2;
		usR2.length = sizeof(pContext->indirectionInfo.r2);

		if((nRet = KM_MakeSessionKey(usR1, usR2, usKIR, &usSessionKey)) != TK_SUCCESS)
			goto error;
	}
	
	// key값 획득 D_SK(KEY)
	if((nRet = TK_Aes128_Decrypt(&usKey, &usE_SK, &usSessionKey)) != TK_SUCCESS)
		goto error;

	// 메모리에  encKey값, 알고리즘, 운영모드 저장
	memcpy(key.key_id, pContext->indirectionInfo.key_id, strlen(pContext->indirectionInfo.key_id));
	memcpy(key.enc_key_value, usKey.value, usKey.length);
	key.key_size = usKey.length;

	if((nRet = KM_EncryptKey(pContext, &key)) != TK_SUCCESS)
		goto error;

	memcpy(key.key_algo, usKeyAlgo.value, usKeyAlgo.length);
	memcpy(key.op_mode, usKeyOPMode.value, usKeyOPMode.length);
	
	if((nRet = KM_SetKeyIntoMemory(pContext, &key)) != TK_SUCCESS)
		goto error;

error:

	memset(&key, 0x00, sizeof(Key));

	TK_Free_UString(&usI_ID);
	TK_Free_UString(&usE_KIR);
	TK_Free_UString(&usE_SK);
	TK_Free_UString(&usKeyAlgo);
	TK_Free_UString(&usKeyOPMode);
	TK_Free_UString(&usKIR);
	TK_Free_UString(&usR1R2);
	TK_Free_UString(&usSessionKey);
	TK_Free_UString(&usKey);

	return nRet;
}

TRUSTKEYSTORE_API void TrustKeystore_Indirect_Final(void **ppCtx)
{
	KM_CtxFree((Agent_Ctx**)ppCtx);
}
#endif


//////////////////////////////////////////////////////////////////////////
// void TrustKeystore_MemFree(void **ppMem)
// 설명 : TrustKeystore 함수 내부에서 할당한 메모리를 해제하는 함수.
// Input : pMem
// Output :
// Return : 성공 0, 실패 errorcode
//////////////////////////////////////////////////////////////////////////
TRUSTKEYSTORE_API void TrustKeystore_MemFree(void **ppMem)
{
	TK_MemFree(ppMem);
}

#if 0
int TrustKeystore_Aes128Cbc_Encrypt(char **ppOut, int *nOutLen, char *pIn, int nInLen, char *pKeyIV)
{
	int nRet = 0;
	UString usOut;

	memset(&usOut, 0x00, sizeof(UString));

	{
		UString usIn, usKeyIV;

		usIn.value		= pIn;
		usIn.length		= nInLen;
		usKeyIV.value	= pKeyIV;
		usKeyIV.length	= 0; // 내부에서 사용되지 않음.

		if((nRet = TK_Aes128_Encrypt(&usOut, &usIn, &usKeyIV)) != TK_SUCCESS)
			goto error;
		*ppOut = usOut.value;
		*nOutLen = usOut.length;
	}

error:
	return nRet;
}

int TrustKeystore_Aes128Cbc_Decrypt(char **ppOut, int *nOutLen, char *pIn, int nInLen, char *pKeyIV)
{
	int nRet = 0;
	UString usOut;
	
	memset(&usOut, 0x00, sizeof(UString));

	{
		UString usIn, usKeyIV;

		usIn.value		= pIn;
		usIn.length		= nInLen;
		usKeyIV.value	= pKeyIV;
		usKeyIV.length	= 0; // 내부에서 사용되지 않음.

		if((nRet = TK_Aes128_Decrypt(&usOut, &usIn, &usKeyIV)) != TK_SUCCESS)
			goto error;
		*ppOut = usOut.value;
		*nOutLen = usOut.length;
	}

error:
	return nRet;
}

int TrustKeystore_Sha256Hash(char *pIn, int nInLen, char *pOut)
{
	int nRet = 0;
	UString usOut;

	memset(&usOut, 0x00, sizeof(UString));

	{
		UString usIn, usKeyIV;

		usIn.value		= pIn;
		usIn.length		= nInLen;

		if((nRet = TK_Sha256Hash(&usIn, &usOut)) != TK_SUCCESS)
			goto error;		

		memcpy(pOut, usOut.value, usOut.length);		
	}

error:
	TK_Free_UString(&usOut);
	return nRet;

}
#endif
