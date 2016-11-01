#include "comm.h"

SOCKET_T g_sockfd;

#ifndef NO_SSL

WOLFSSL *g_ssl;

int TK_COMM_INIT(void **sslCtx, char* szSSLServerCACertFile, char*szSSLServerCACertPath)
{
	int nRet = 0;

	WOLFSSL_METHOD*  method  = 0;
	char verifyCert[MAX_PATH] = {0};

	PRINT_DEBUG("[ TK_COMM_INIT ] Start.");

	StartTCP();
	if(wolfSSL_Init() != SSL_SUCCESS)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_COMM_INIT_SSL;
		goto error;
	}

	if ((method = wolfTLSv1_2_client_method()) == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_COMM_INIT_SSLMETHOD;
		goto error;
	}

	if((*sslCtx = wolfSSL_CTX_new(method)) == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_COMM_INIT_SSLCONTEXT;
		goto error;
	}

// 	if(wolfSSL_CTX_set_timeout((WOLFSSL_CTX*)*sslCtx, 5) != SSL_SUCCESS)
// 	{
// 		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_COMM_INIT_SSL_SETTIMEOUT;
// 		goto error;
// 	}

	// 서버 검증용 ca 인증서 로딩 부분
	sprintf(verifyCert, "%s/%s", szSSLServerCACertPath, szSSLServerCACertFile);
	// 
	// 	PRINT_DEBUG("SSL Server Ca Cert File Name");
	// 	PRINT_DEBUG(verifyCert);

	if(wolfSSL_CTX_load_verify_locations((WOLFSSL_CTX*)*sslCtx, verifyCert, NULL) != SSL_SUCCESS)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_COMM_INIT_SSLCACERT;
		goto error;
	}

	// 서버 검증 하지 않음
	//wolfSSL_CTX_set_verify((WOLFSSL_CTX*)*sslCtx, SSL_VERIFY_NONE, 0);

	PRINT_DEBUG("Init Wolf SSL Success.");

error:

	PRINT_DEBUG("[ TK_COMM_INIT ] End.\n");

	return nRet;
}

int TK_Connect(void *sslCtx, char *ip, unsigned short port, int doDtls)
{
	int nRet = 0;

	if((g_ssl = wolfSSL_new((WOLFSSL_CTX*)sslCtx)) == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_COMM_CONNECT_SSL_NEW;
		goto error;
	}
	PRINT_DEBUG("wolfSSL_new OK.");

	if((nRet = tcp_connect(&g_sockfd, ip, (word16)port, doDtls)) != TK_SUCCESS)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_COMM_CONNECT_TCP_CONNECT;
		goto error;
	}
	PRINT_DEBUG("tcp_connect OK.");	

	if(wolfSSL_set_fd(g_ssl, g_sockfd) != SSL_SUCCESS)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_COMM_CONNECT_SSL_SETFD;
		goto error;
	}
	PRINT_DEBUG("wolfSSL_set_fd OK.");	

	// 통신
	if (wolfSSL_connect(g_ssl) != SSL_SUCCESS)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_COMM_CONNECT_SSL_CONNECT;
		goto error;
	}
	PRINT_DEBUG("wolfSSL_connect OK.");	

// 	showPeer(g_ssl);

error:
	return nRet;
}

void TK_Disconnect()
{
	wolfSSL_shutdown(g_ssl);
	wolfSSL_free(g_ssl);
	g_ssl = NULL;
	CloseSocket(g_sockfd);
}

int TK_SEND(char *szSendMsg, int nSendSz)
{
	int nRet = 0;

	if (wolfSSL_write(g_ssl, szSendMsg, nSendSz) != nSendSz)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_COMM_SEND;
		goto error;
	}
	
error:
	return nRet;
}

int TK_RECV(char *szRecvMsg, int nRecvBuffSz)
{
	int nRet = 0;

	if((nRet = wolfSSL_read(g_ssl, szRecvMsg, nRecvBuffSz)) > 0)
	{
		szRecvMsg[nRet] = 0;
	}
	else
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_COMM_RECV;
	}

	return nRet;
}
void TK_COMM_FINAL(void **sslCtx)
{
	wolfSSL_CTX_free((WOLFSSL_CTX*)*sslCtx);
	*sslCtx = NULL;
	wolfSSL_Cleanup();
	EndTCP();
}

#else // 경량 Agent

int TK_COMM_INIT(void **sslCtx, char* szSSLServerCACertFile, char*szSSLServerCACertPath)
{
	int nRet = 0;
	
	PRINT_DEBUG("[ TK_COMM_INIT ] Start.");

	StartTCP();
	
	PRINT_DEBUG("Init HTTP Success.");

	PRINT_DEBUG("[ TK_COMM_INIT ] End.\n");

	return nRet;
}

int TK_Connect(void *sslCtx, char *ip, unsigned short port, int doDtls)
{
	int nRet = 0;

	if((nRet = tcp_connect(&g_sockfd, ip, (word16)port, doDtls)) != TK_SUCCESS)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_COMM_CONNECT_TCP_CONNECT;
		goto error;
	}
	PRINT_DEBUG("tcp_connect OK.");	

error:
	return nRet;
}

void TK_Disconnect()
{
	CloseSocket(g_sockfd);	
}

int TK_SEND(char *szSendMsg, int nSendSz)
{
	int nRet = 0;

	if(send(g_sockfd, szSendMsg, nSendSz, 0) != nSendSz)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_COMM_SEND;
		goto error;
	}

error:
	return nRet;
}

int TK_RECV(char *szRecvMsg, int nRecvBuffSz)
{
	int nRet = 0;

	if((nRet = recv(g_sockfd, szRecvMsg, nRecvBuffSz, 0)) > 0)
	{
		szRecvMsg[nRet] = 0;
	}
	else
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_COMM_RECV;
	}

	return nRet;
}

void TK_COMM_FINAL(void **sslCtx)
{
	EndTCP();
}

#endif

int TK_HTTP_RECV(char **szRecvMsg, int *nRecvBuffSz)
{
	int nRet = 0;
	char reply[1024] = {0};
	int nReceived = 0;
	char SSL_Reply[7] = {21,3,1,0,2,2,10};

	if((nReceived = TK_RECV(reply, sizeof(reply)-1)) > 0)
	{
		int nContentLen = 0;
		int nRemainLen = 0;
		char *pPos = NULL;

		if(memcmp(reply, SSL_Reply, sizeof(SSL_Reply)) == 0)
		{
			nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_COMM_SSL;
			goto error;
		}

		if((pPos = strstr(reply, "Content-Length:")) == NULL)
		{
			nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_COMM_HTTP_RECV;
			goto error;
		}
		pPos += strlen("Content-Length: ");
		nContentLen = nRemainLen = strtol(pPos, NULL, 10);

		if(nContentLen <= 0)
		{
			goto error;
		}

		if((*szRecvMsg = (char*) TK_MemAlloc(nContentLen + 1)) == NULL)
		{
			nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
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
			if((nReceived = TK_RECV(*szRecvMsg + *nRecvBuffSz, nRemainLen)) > 0)
			{
				*nRecvBuffSz += nReceived;
				nRemainLen -= nReceived;
			}
			else
			{
				nRet = g_nAgentErrorCode = nReceived;
				goto error;
			}
		}
	}
	else
	{
		nRet = g_nAgentErrorCode = nReceived;
		goto error;
	}
error:

	return nRet;

}
