#ifndef COMM_H
#define COMM_H

#include "SSLSettings.h"

int COMM_INIT(void **sslCtx, char* szSSLServerCACertFile, char*szSSLServerCACertPath);
int Connect(void *sslCtx, char *ip, unsigned short port, int doDtls);
void Disconnect();
int SEND(char *szSendMsg, int nSendSz);
int RECV(char *szRecvMsg, int nRecvBuffSz);
void COMM_FINAL(void **sslCtx);

int HTTP_RECV(char **szRecvMsg, int *nRecvBuffSz);

#endif
