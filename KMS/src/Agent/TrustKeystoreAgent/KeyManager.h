#ifndef KEYMANAGER_H
#define KEYMANAGER_H

#include "util.h"
#include "comm.h"
#include "crypto.h"
#include "ProtocolManager.h"
#include "keydb.h"

// ip정보 얻어오는 lib
#ifdef WIN32
	#include <iphlpapi.h>
	#pragma comment(lib, "iphlpapi.lib")
#else	// tested on linux, aix
	#include <net/if.h>
	#include <netinet/in.h>
	#include <sys/ioctl.h>
#endif

#ifdef SOLARIS
	#include <sys/sockio.h> 
#endif 


#define AGENT_CONF_FILE_NAME	"trustKeystoreAgent.conf"

//////////////////////////////////////////////////////////////////////////
int KM_GetKey(Agent_Ctx *pContext, char* szKeyID, Key *pKey);
int KM_CheckKeyDBFile(Agent_Ctx *pContext);
int KM_GetKeyFromKeyDBFile(Agent_Ctx *pContext, char* szKeyID, Key *pKey);
int KM_GetKeyFromMemory(Agent_Ctx *pContext, char* szKeyID, Key *pKey);
int KM_GetKeyFromKMS(Agent_Ctx *pContext, char* szKeyID, Key *pKey);

int KM_SetKeyIntoMemory(Agent_Ctx *pContext, Key *pKey);
int KM_SetKeyListIntoMemory(Agent_Ctx *pContext, KeyList *pKeyList);

int KM_GetKeyListFromKMS(Agent_Ctx *pContext, char* szKeyIDList, KeyList *pKeyList);
int KM_GetUpdateAvailableKeyIDList(Agent_Ctx *pContext, char* szKeyIDListIn, char** szKeyIDListOut);
int KM_MakeRequest(Agent_Ctx *pContext, int nOPCode, char* szArg, char** szRequest);
int KM_RequestToKMS(Agent_Ctx *pContext, char* szSendMsg, char** szRecvMsg);
int KM_VerifyKeyHMAC(Agent_Ctx *pContext, Key *pKey);
int KM_VerifyKeyValidDate(Agent_Ctx *pContext, Key *pKey);
int KM_VerifyKeyExposeLevel(Agent_Ctx *pContext, Key *pKey, int nUsage);

int KM_InitComm(Agent_Ctx *pContext);

int KM_CheckCtx(Agent_Ctx *pContext);
void KM_CtxFree(Agent_Ctx **ppContext);
int KM_SetConfig(Agent_Ctx *pContext, char *szConfPath);
int KM_VerifyAgentHint(Agent_Ctx *pContext);
int KM_VerifyIntegrity(Agent_Ctx *pContext);
int KM_Make_Agent_HMAC(Agent_Ctx *pContext);
int KM_Make_KeyFromMaterial(UString *pMaterial, UString *pKey);
int KM_Make_KEK_Material(Agent_Ctx *pContext);
int KM_Make_KEK(Agent_Ctx *pContext, UString *pKek);
int KM_EncryptKey(Agent_Ctx *pContext, Key *pKey);
int KM_DecryptKey(Agent_Ctx *pContext, Key *pKey);

int KM_MakeKIR(char* I_ID, char* R_ID, UString usRandom2, UString *pusKIR);
int KM_MakeSessionKey(UString usRandom1, UString usRandom2, UString usKIR, UString *pusSessionKey);

void KM_ComputeXOR_IND_BLOCK(char *a, char *b, char *r);
#endif // KEYMANAGER_H
