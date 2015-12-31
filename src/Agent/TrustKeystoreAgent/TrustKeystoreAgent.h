#ifndef TRUSTKEYSTOREAGENT_H
#define TRUSTKEYSTOREAGENT_H

#if defined (WIN32) && !defined(TKS_BUILD_STATIC)
	#if defined (TRUSTKEYSTOREAGENT_EXPORTS) || (TKSAGENTADV_EXPORTS) || (TKSAGENT_EXPORTS) || (TKSAGENTLITE_EXPORTS)
		#define TRUSTKEYSTORE_API __declspec(dllexport)
	#else
		#define TRUSTKEYSTORE_API __declspec(dllimport)
	#endif
#elif defined(LINUX) || (linux) || (AIX)
	//  GCC
	#if defined (TRUSTKEYSTOREAGENT_EXPORTS) || (TKSAGENTADV_EXPORTS) || (TKSAGENT_EXPORTS) || (TKSAGENTLITE_EXPORTS)
		#define TRUSTKEYSTORE_API __attribute__((visibility("default")))
	#else
		#define TRUSTKEYSTORE_API
	#endif
#else
	#define TRUSTKEYSTORE_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef INDIRECT_AGENT
	TRUSTKEYSTORE_API int TrustKeystore_Init(void **ppCtx, char * szConfPath);
	TRUSTKEYSTORE_API int TrustKeystore_GetKey(void *pCtx, char* szKeyID, char **keyValue, int* keyLen);
	TRUSTKEYSTORE_API int TrustKeystore_GetKeyAlgo(void *pCtx, char* szKeyID, char **szKeyAlgo);
	TRUSTKEYSTORE_API int TrustKeystore_GetKeyOPMode(void *pCtx, char* szKeyID, char **szKeyOPMode);
	TRUSTKEYSTORE_API int TrustKeystore_GetKeyInfo(void *pCtx, char* szKeyID, char **szKeyInfo);
	TRUSTKEYSTORE_API int TrustKeystore_GetEncKey(void *pCtx, char* szKeyID, char **encKeyValue, int* keyLen);
	TRUSTKEYSTORE_API int TrustKeystore_GetEncKeyInfo(void *pCtx, char* szKeyID, char **szEncKeyInfo);
	TRUSTKEYSTORE_API int TrustKeystore_UpdateKey(void *pCtx, char* szKeyIDList);
	TRUSTKEYSTORE_API int TrustKeystore_Encrypt(void *pCtx, char* szKeyID, char* in, int inLen, char **ppOut, int *outLen);
	TRUSTKEYSTORE_API int TrustKeystore_Decrypt(void *pCtx, char* szKeyID, char* in, int inLen, char **ppOut, int *outLen);
	TRUSTKEYSTORE_API int TrustKeystore_GetErrorCode();
	TRUSTKEYSTORE_API char* TrustKeystore_GetErrorStr(int nErrorCode);
	TRUSTKEYSTORE_API void TrustKeystore_Final(void **ppCtx);

	TRUSTKEYSTORE_API int TrustKeystore_Indirect_MakeResponseKeyMsg(void *pCtx, char* szDeviceID, char *RequestMsg, int RequestLen, char **ResponseMsg, int* ResponseLen);
#endif

#ifndef DIRECT_AGENT
	// functions for indirect agent device
	TRUSTKEYSTORE_API int TrustKeystore_Indirect_Init(void **ppCtx);
	TRUSTKEYSTORE_API int TrustKeystore_Indirect_GetKey(void *pCtx, char* szKeyID, char **keyValue, int* keyLen);
	TRUSTKEYSTORE_API int TrustKeystore_Indirect_GetKeyAlgo(void *pCtx, char* szKeyID, char **szKeyAlgo);
	TRUSTKEYSTORE_API int TrustKeystore_Indirect_GetKeyOPMode(void *pCtx, char* szKeyID, char **szKeyOPMode);
	TRUSTKEYSTORE_API int TrustKeystore_Indirect_MakeRequestKeyMsg(void *pCtx, char* szDeviceID, char* szKeyID, char **RequestMsg, int* RequestLen);
	TRUSTKEYSTORE_API int TrustKeystore_Indirect_SetKey(void *pCtx, char *ResponseMsg, int ResponseLen);
	TRUSTKEYSTORE_API void TrustKeystore_Indirect_Final(void **ppCtx);
#endif

	// common
	TRUSTKEYSTORE_API void TrustKeystore_MemFree(void **ppMem);

#if 0
// 추가 기능
TRUSTKEYSTORE_API int TrustKeystore_Aes128Cbc_Encrypt(char **ppOut, int *nOutLen, char *pIn, int nInLen, char *pKeyIV);
TRUSTKEYSTORE_API int TrustKeystore_Aes128Cbc_Decrypt(char **ppOut, int *nOutLen, char *pIn, int nInLen, char *pKeyIV);
TRUSTKEYSTORE_API int TrustKeystore_Sha256Hash(char *pIn, int nInLen, char *pOut);
#endif
// 함수 포인터
// #define P_TK_INIT (int (__cdecl*)(void**, char*))
// int (__cdecl *pTrustKeystore_Init)(void**, char*);
// #define P_TK_GETKEY (int (__cdecl*)(void *, char*, char**, int*))
// int (__cdecl *pTrustKeystore_GetKey)(void *, char*, char**, int*);
// 
// #define P_TK_MEMFREE (void (__cdecl*)(void *))
// void (__cdecl *pTrustKeystore_MemFree)(void *pMem);

#ifdef __cplusplus
}
#endif

#endif //TRUSTKEYSTOREAGENT_H
