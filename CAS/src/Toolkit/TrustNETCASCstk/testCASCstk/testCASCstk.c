#include <stdio.h>
#include <stdlib.h>

#ifdef WIN32
	#include <Windows.h>
	#include <time.h>
	#pragma comment (lib, "../debug/TrustNETCASCstk.lib")	
#else
	#include <sys/time.h>
	#include <sys/param.h>
#endif

#ifndef MAX_PATH
	#define MAX_PATH 260
#endif

#include "../TrustNETCASCstk/TrustNETCASCstk.h"

int main(char *argc, char *argv[])
{
	int nRet = 0;
	char szGatewayID[] = "LGU_SmartPlug_111111112";
	char szDeviceID[] = "LGU_SmartPlug_111111113";
	char *pAuthKey = NULL;
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

	if((nRet = TK_Init(szModulePath)) != 0)
		goto err;
	
	if((nRet = TK_IssueCert(szGatewayID)) != 0)
		goto err;

	if((nRet = TK_Sign(szGatewayID, szDeviceID, &pAuthKey)) != 0)
		goto err;

	printf("AuthKey : %s\n", pAuthKey);

err:
	if(nRet)
	{
		printf("error : [%d]\n", nRet);
	}

	TK_Final();

	if(pAuthKey)
		free(pAuthKey);

	return nRet;
}
