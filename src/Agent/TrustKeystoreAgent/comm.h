#ifndef COMM_H
#define COMM_H

#include "util.h"
#include "SSLSettings.h"

int TK_COMM_INIT(void **sslCtx, char* szSSLServerCACertFile, char*szSSLServerCACertPath);
int TK_Connect(void *sslCtx, char *ip, unsigned short port, int doDtls);
void TK_Disconnect();
int TK_SEND(char *szSendMsg, int nSendSz);
int TK_RECV(char *szRecvMsg, int nRecvBuffSz);
void TK_COMM_FINAL(void **sslCtx);

int TK_HTTP_RECV(char **szRecvMsg, int *nRecvBuffSz);

#endif
