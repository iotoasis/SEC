#include "comm.h"

SOCKET_T g_sockfd;
WOLFSSL *g_ssl;

int COMM_INIT(void **sslCtx, char* szSSLServerCACertFile, char*szSSLServerCACertPath)
{
	int nRet = 0;
	WOLFSSL_METHOD*  method  = 0;
	char verifyCert[260] = {0};

	StartTCP();
	if(wolfSSL_Init() != SSL_SUCCESS)
	{
		nRet = -1;
		goto error;
	}

	if((method = wolfTLSv1_2_client_method()) == NULL)
	{
		nRet = -1;
		goto error;
	}

	if((*sslCtx = wolfSSL_CTX_new(method)) == NULL)
	{
		nRet = -1;
		goto error;
	}

	// 서버 검증용 ca 인증서 로딩 부분
	sprintf(verifyCert, "%s/%s", szSSLServerCACertPath, szSSLServerCACertFile);

	if(wolfSSL_CTX_load_verify_locations((WOLFSSL_CTX*)*sslCtx, verifyCert, NULL) != SSL_SUCCESS)
	{
		nRet = -1;
		goto error;
	}

error:

	return nRet;
}

int Connect(void *sslCtx, char *ip, unsigned short port, int doDtls)
{
	int nRet = 0;

	if((g_ssl = wolfSSL_new((WOLFSSL_CTX*)sslCtx)) == NULL)
	{
		nRet = -1;
		goto error;
	}

	if((nRet = tcp_connect(&g_sockfd, ip, (word16)port, doDtls)) != 0)
	{
		nRet = -1;
		goto error;
	}

	if(wolfSSL_set_fd(g_ssl, g_sockfd) != SSL_SUCCESS)
	{
		nRet = -1;
		goto error;
	}

	// 통신
	if (wolfSSL_connect(g_ssl) != SSL_SUCCESS)
	{
		nRet = -1;
		goto error;
	}

error:
	return nRet;
}

void Disconnect()
{
	wolfSSL_shutdown(g_ssl);
	wolfSSL_free(g_ssl);
	g_ssl = NULL;
	CloseSocket(g_sockfd);
}

int SEND(char *szSendMsg, int nSendSz)
{
	int nRet = 0;

	if (wolfSSL_write(g_ssl, szSendMsg, nSendSz) != nSendSz)
	{
		nRet = -1;
		goto error;
	}
	
error:
	return nRet;
}

int RECV(char *szRecvMsg, int nRecvBuffSz)
{
	int nRet = 0;

	if((nRet = wolfSSL_read(g_ssl, szRecvMsg, nRecvBuffSz)) > 0)
	{
		szRecvMsg[nRet] = 0;
	}
	else
	{
		nRet = -1;
	}

	return nRet;
}
void COMM_FINAL(void **sslCtx)
{
	wolfSSL_CTX_free((WOLFSSL_CTX*)*sslCtx);
	*sslCtx = NULL;
	wolfSSL_Cleanup();
	EndTCP();
}

int HTTP_RECV(char **szRecvMsg, int *nRecvBuffSz)
{
	int nRet = 0;
	char reply[1024] = {0};
	int nReceived = 0;
	char SSL_Reply[7] = {21,3,1,0,2,2,10};

	if((nReceived = RECV(reply, sizeof(reply)-1)) > 0)
	{
		int nContentLen = 0;
		int nRemainLen = 0;
		char *pPos = NULL;

		if(memcmp(reply, SSL_Reply, sizeof(SSL_Reply)) == 0)
		{
			nRet = -1;
			goto error;
		}

		if((pPos = strstr(reply, "Content-Length:")) == NULL)
		{
			nRet = -1;
			goto error;
		}
		pPos += strlen("Content-Length: ");
		nContentLen = nRemainLen = strtol(pPos, NULL, 10);

		if(nContentLen <= 0)
		{
			nRet = -1;
			goto error;
		}

		if((*szRecvMsg = (char*) calloc(nContentLen + 1, 1)) == NULL)
		{
			nRet = -1;
			goto error;
		}

		while(*pPos != '\r' && *pPos != '\n')
		{
			pPos++;
		}

		while(*pPos == '\r' || *pPos == '\n')
		{
			pPos++;
		}

		if(strlen(pPos) > 0)
		{
			*nRecvBuffSz = strlen(pPos);
			strncpy(*szRecvMsg, pPos, *nRecvBuffSz);
			nRemainLen = nContentLen - *nRecvBuffSz;
		}		

		while(nRemainLen > 0)
		{
			if((nReceived = RECV(*szRecvMsg + *nRecvBuffSz, nRemainLen)) > 0)
			{
				*nRecvBuffSz += nReceived;
				nRemainLen -= nReceived;
			}
			else
			{
				nRet = -1;
				goto error;
			}
		}
	}
	else
	{
		nRet = -1;
		goto error;
	}
error:

	return nRet;
}
