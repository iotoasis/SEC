#ifndef CERTMANAGER_H
#define CERTMANAGER_H

#include "casClientConfig.h"
#include "crypto.h"
#include "comm.h"
#include "protocolManager.h"
#include "util.h"
#include "error.h"

int CM_RegDeviceGetDN(Client_CTX *pCtx, char *szDeviceID, char **szDN, char **szKeyAlgo, char **szKeyLength);
int CM_IssueCertSimple(Client_CTX *pCtx, char *szDeviceID, char *szDN, char *szKeyAlgo, char *szKeyLength, char *szPass, char **szCert, char **szPriKey);
int CM_AuthByCert(Client_CTX *pCtx, char *szID, char *szSignValue, char *szSignCert, char **szAuthKey);

int CM_ReqToCAServer(Client_CTX *pCtx, char *reqPage, char *szMsg, char **szResponse);

int CM_MakeCertPass(char *szDeviceID, char **szPass);
int CM_SaveCertSet(char *szDeviceID, char *szCert, char *szPriKey);
int CM_GetCertSet(char *szDeviceID, char **szCert, char **szPriKey);
char* CM_GetCertDir(char *szDeviceID);
int CM_VerifyCert(char *szDeviceID);

int CM_InitContext(Client_CTX **ppCtx);
int CM_CheckContext(Client_CTX *pCtx);
int CM_CheckDeviceID(Client_CTX *pCtx, char *szDeviceID);
int CM_FinalContext(Client_CTX **pCtx);
int CM_SetConfig(Client_CTX *pCtx, char *szConfPath);
int CM_InitComm(Client_CTX *pCtx);
void CM_FinalComm(Client_CTX *pCtx);

void CM_MemFree(void **ppMem);

#endif
