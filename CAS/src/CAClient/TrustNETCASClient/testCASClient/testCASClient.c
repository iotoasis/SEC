#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
	#include <Windows.h>
	#include <time.h>
	#pragma comment (lib, "../debug/TrustNETCASClient.lib")	
#else
	#include <sys/time.h>
	#include <sys/param.h>
#endif

#include "../TrustNETCASClient/TrustNETCASClient.h"

int g_time;

#ifndef MAX_PATH
	#define MAX_PATH 260
#endif

#ifdef WIN32

#define TIME_START 	g_time = clock();
#define TIME_END	g_time = clock() - g_time; 	printf("Time : %.3f sec\n", ((double)(g_time)) / CLOCKS_PER_SEC);
#define TIME(t)	t = clock() - g_time;

#else
#define TIME_START	g_time = timeGetTime();
#define TIME_END	g_time = timeGetTime() - g_time; printf("Time : %.3f sec\n", (double)g_time / 1000);
#define TIME(t)	t = timeGetTime() - g_time;

int timeGetTime()
{
	struct timeval tv;
	gettimeofday( &tv, NULL );
	return ( ( tv.tv_sec * 1000 ) + ( tv.tv_usec / 1000 ) );
}

#endif

#ifdef WIN32
#define SLEEP_SECONDS(x)	Sleep(x * 1000);
#else
#define SLEEP_SECONDS(x)	sleep(x);
#endif

int ttaTest(char *szModulePath)
{
	int nRet = 0;
	int nTime = 0;
	int nCertCount = 0;
	void *pContext = NULL;
	FILE *pFile = NULL;
	char szDeviceID[] = "hbwootest";
	char szSignSrc[] = "This is sign src.";
	char *pCert = NULL;
	char *pPriKey = NULL;
	char *pPass = NULL;
	char *pSign = NULL;

	printf("\n\n************************************************************\n");
	printf("TrustNetCAS TTA test.\n");
	printf("Issue certificate during 60 seconds.\n");		
	printf("************************************************************\n");
	printf("\n");

	if((nRet = TrustNet_Init(&pContext, szModulePath)) != 0)
	{
		printf("TrustNet_Init Failed!\n");
		goto err;
	}

	strcat(szModulePath, "/TTATest.log");

	if((pFile = fopen(szModulePath, "w")) == NULL)
	{
		printf("Can't open file.\n");
		goto err;
	}

	TIME_START;

	while(1)
	{

		TIME(nTime);

		if(nTime)
		{
			printf("\rElapsed time : %02dsec\tCert count : %d", nTime/1000, nCertCount);
			fflush(NULL);
		}

		if(nTime >= 60 * 1000)	// 1분
		{
			break;
		}

		if((nRet = TrustNet_IssueDeviceCert(pContext, szDeviceID, CERT_REISSUE)) != 0)
		{
			printf("\nTrustNet_IssueDeviceCert Failed!\n");
			goto err;
		}

		if((nRet = TrustNet_GetDeviceCert(pContext, szDeviceID, &pCert)) != 0)
		{
			printf("\nTrustNet_GetDeviceCert Failed!\n");
			goto err;
		}

		fprintf(pFile, "[%d]Cert : \n", nCertCount + 1);
		fprintf(pFile, "%s\n", pCert);

		if(pCert) {	free(pCert); pCert = NULL; }

		if((nRet = TrustNet_GetDevicePrikeyAndPass(pContext, szDeviceID, &pPriKey, &pPass)) != 0)
		{
			printf("\nTrustNet_GetDevicePrikeyAndPass Failed!\n");
			goto err;
		}

		fprintf(pFile, "[%d]PriKey : \n", nCertCount + 1);
		fprintf(pFile, "%s\n", pPriKey);

		if(pPriKey)	{	free(pPriKey);	pPriKey = NULL;	}
		if(pPass)	{	free(pPass);	pPass = NULL;	}

		nCertCount++;
	}

	fprintf(pFile, "\nTotal issued cert count : %d\n", nCertCount);
	fprintf(pFile, "Elapsed time : %dms\n", nTime);

	// 전자서명 / 검증
	printf("\nSign and verify test result...");

	if((nRet = TrustNet_GetDevicePrikeyAndPass(pContext, szDeviceID, &pPriKey, &pPass)) != 0)
	{
		printf("\nTrustNet_GetDevicePrikeyAndPass Failed!\n");
		goto err;
	}

	if((nRet = TrustNet_SignTest(szSignSrc, pPriKey, pPass, &pSign)) != 0)
	{
		printf("\nTrustNet_SignTest Failed!\n");
		goto err;
	}

	if((nRet = TrustNet_GetDeviceCert(pContext, szDeviceID, &pCert)) != 0)
	{
		printf("\nTrustNet_GetDeviceCert Failed!\n");
		goto err;
	}

	if((nRet = TrustNet_VerifyTest(szSignSrc, pSign, pCert)) != 0)
	{
		printf("\nTrustNet_SignTest Failed!\n");
		goto err;
	}
	else
	{
		printf("Success.\n");
	}

	// 서명 검증 로그
	fprintf(pFile, "\n*** Sign and verify test. ***\n");
	fprintf(pFile, "Sign src : %s\n", szSignSrc);
	fprintf(pFile, "Sign value : %s\n", pSign);
	fprintf(pFile, "Sign cert : %s\n", pCert);
	fprintf(pFile, "Verify success.\n");

	printf("\nTest Complete.\n");
	printf("For details, see TTATest.log\n");


	TrustNet_Final((void **)(&pContext));

err:
	if(pFile)
		fclose(pFile);
	if(pCert)	{	free(pCert);	pCert = NULL;	}
	if(pPriKey)	{	free(pPriKey);	pPriKey = NULL;	}
	if(pPass)	{	free(pPass);	pPass = NULL;	}
	if(pSign)	{	free(pSign);	pSign = NULL;	}


	if(nRet != 0)
		printf("\nerrcode : %d\n", nRet);

	return 0;
}

int icbmsDemo(char *szModulePath)
{
	int nRet = 0;
	void *pContext = NULL;
	char szDeviceGatewayID[] = "UnetDeviceGateway";
	char szDeviceID[] = "UnetDevice";
	char *pCert = NULL;
	char *pPriKey = NULL;
	char *pPass = NULL;
	char *pSign = NULL;
	char *pAuthKey = NULL;

	printf("\n\n************************************************************\n");
	printf("TrustNetCAS Demo.\n");
	printf("************************************************************\n");
	printf("\n");

	if((nRet = TrustNet_Init(&pContext, szModulePath)) != 0)
	{
		printf("TrustNet_Init Failed!\n");
		goto err;
	}

	if((nRet = TrustNet_IssueDeviceCert(pContext, szDeviceGatewayID, CERT_REISSUE)) != 0)
	{
		printf("\nTrustNet_IssueDeviceCert Failed!\n");
		goto err;
	}

	if((nRet = TrustNet_GetDeviceCert(pContext, szDeviceGatewayID, &pCert)) != 0)
	{
		printf("\nTrustNet_GetDeviceCert Failed!\n");
		goto err;
	}

	if(pCert) {	free(pCert); pCert = NULL; }

	if((nRet = TrustNet_GetDevicePrikeyAndPass(pContext, szDeviceGatewayID, &pPriKey, &pPass)) != 0)
	{
		printf("\nTrustNet_GetDevicePrikeyAndPass Failed!\n");
		goto err;
	}

	if((nRet = TrustNet_SignTest(szDeviceID, pPriKey, pPass, &pSign)) != 0)
	{
		printf("\nTrustNet_SignTest Failed!\n");
		goto err;
	}

	if((nRet = TrustNet_GetAuthKeyFromMEF(pContext, szDeviceGatewayID, szDeviceID, pSign, &pAuthKey)) != 0)
	{
		printf("\nTrustNet_GetAuthKeyFromMEF Failed!\n");
		goto err;
	}

	TrustNet_Final((void **)(&pContext));

	printf("\n\n************************************************************\n");
	printf("End.\n");
	printf("************************************************************\n");
	printf("\n");

err:
	if(pCert)	{	free(pCert);	pCert = NULL;	}
	if(pPriKey)	{	free(pPriKey);	pPriKey = NULL;	}
	if(pPass)	{	free(pPass);	pPass = NULL;	}
	if(pSign)	{	free(pSign);	pSign = NULL;	}
	if(pAuthKey){	free(pAuthKey);	pAuthKey = NULL;}

	if(nRet != 0)
		printf("\nerrcode : %d\n", nRet);

	return 0;
}

int main(char *argc, char *argv[])
{
	char szModulePath[MAX_PATH] = {0};
	char *pPos = NULL;

#ifdef WIN32
	GetModuleFileNameA(NULL, szModulePath, MAX_PATH);
	pPos = strrchr(szModulePath, '\\');
	*pPos = 0;
#else
	realpath(argv[0], szModulePath);
	pPos = strrchr(szModulePath, '/');
	*pPos = 0;
#endif

	//ttaTest(szModulePath);
	icbmsDemo(szModulePath);

	return 0;
}
