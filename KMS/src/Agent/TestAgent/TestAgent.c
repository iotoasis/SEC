// TestAgent.c : 콘솔 응용 프로그램에 대한 진입점을 정의합니다.

#include <stdio.h>
#include <string.h>

#ifdef WIN32
#include <time.h>
#if defined (TEST_TKS_AGENT)
#pragma comment (lib, "../lib/TKSAgent.lib")
#elif defined (TEST_TKS_AGENT_ADV)
#pragma comment (lib, "../lib/TKSAgentAdv.lib")
#elif defined (TEST_TKS_AGENT_LITE)
#pragma comment (lib, "../lib/TKSAgentLite.lib")
#else
#pragma comment (lib, "../lib/TrustKeystoreAgent.lib")
#endif
#else
#include <sys/time.h>
#endif

#include "../TrustKeystoreAgent/TrustKeystoreAgent.h"

int g_time;

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

void menu()
{	
	printf("\n****************************************************\n");
	printf("1. Call TrustKeystore_Init()\n");
	printf("2. Call TrustKeystore_GetKey()\n");
	printf("3. Call TrustKeystore_GetKeyAlgo()\n");
	printf("4. Call TrustKeystore_GetKeyOPMode()\n");
	printf("5. Call TrustKeystore_GetKeyInfo()\n");
	printf("6. Call TrustKeystore_GetEncKey()\n");
	printf("7. Call TrustKeystore_GetEncKeyInfo()\n");	
	printf("8. Call TrustKeystore_UpdateKey()\n");
	printf("9. Call TrustKeystore_Encrypt()\n");
	printf("10. Call TrustKeystore_Decrypt()\n");
	printf("11. Indirect Key Simulation()\n");
	printf("12. Call TrustKeystore_Final()\n");
#if 0
	printf("12. Aes128Cbc Encrypt / Decrypt example\n");
	printf("13. Sha256 Hash example\n");
#endif
	printf("To exit press any other key. \n");
}

int test(int nNum)
{
	int nRet = 0, nError = 0;
	static void * pCtx = NULL;
#ifdef WIN32
	char * szConfPath = "c:\\TrustNet";
#else
	char * szConfPath = "./";
#endif
	int ntime = 0;
	char szKeyID_enc[] = "hbwoo_3";	// static key
	char szKeyID_d[] = "sample_d2";	// dynamic key
	char szKeyID_Ind[] = "hbwoo_12";	//"HMAC-SHA256";
	static char szInKey[256] = {0};
	
	char szDeviceID1[] = "test_device1";
	char szDeviceID2[] = "test_device2";
	static char szPlainText[256] = {0};
	static char *EncText = NULL;
	static int EncLen = 0;
	char *DecText = NULL;
	char *keyValue = NULL;
	char *keyAlgo = NULL;
	char *keyOpMode = NULL;
	char *szKeyInfo = NULL;
	char *reqMsg = NULL;
	char *resMsg = NULL;
	int DecLen = 0,keyLength = 0, reqMsgLen = 0, resMsgLen = 0;
	int i,j;
	
	TIME_START;

	switch(nNum)
	{
#ifndef TEST_TKS_AGENT_LITE
	case 1:
		if((nError = TrustKeystore_Init(&pCtx, szConfPath)) != 0)
		{
			printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
		}
		else
		{
			printf("config path : %s\n", szConfPath);
			printf("Init Success\n");
		}
		break;
	case 2:
		{
			printf("enter key id : ");
			scanf("%s", szInKey);

			TIME_START;

			if((nError = TrustKeystore_GetKey(pCtx, szInKey, &keyValue, &keyLength)) != 0)
			{
				printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
			}
			else
			{
				printf("Key[%d] : ", keyLength);
				for(i = 0; i < keyLength; i++)
				{
					printf("%02x", (unsigned char)keyValue[i]);
				}
				printf("\n");
			}
			TrustKeystore_MemFree((void**)&keyValue);
		}
		break;
	case 3:
		{
			printf("enter key id : ");
			scanf("%s", szInKey);

			TIME_START;

			if((nError = TrustKeystore_GetKeyAlgo(pCtx, szInKey, &keyAlgo)) != 0)
			{
				printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
			}
			else
				printf("Key Algo : %s\n", keyAlgo);

			TrustKeystore_MemFree((void**)&keyAlgo);
		}
		break;
	case 4:
		{
			printf("enter key id : ");
			scanf("%s", szInKey);

			TIME_START;

			if((nError = TrustKeystore_GetKeyOPMode(pCtx, szInKey, &keyOpMode)) != 0)
			{
				printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
			}
			else
				printf("Key OpMode : %s\n", keyOpMode);

			TrustKeystore_MemFree((void**)&keyOpMode);
		}
		break;
	case 5:
		{
			printf("enter key id : ");
			scanf("%s", szInKey);

			TIME_START;

			if((nError = TrustKeystore_GetKeyInfo(pCtx, szInKey, &szKeyInfo)) != 0)
			{
				printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
			}
			else
			{
				printf("Key Info : %s\n", szKeyInfo);
			}
			TrustKeystore_MemFree((void**)&szKeyInfo);
		}
		break;
	case 6:
		{
			printf("enter key id : ");
			scanf("%s", szInKey);

			TIME_START;

			if((nError = TrustKeystore_GetEncKey(pCtx, szInKey, &keyValue, &keyLength)) != 0)
			{
				printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
			}
			else
			{
				printf("EncKey[%d] : ", keyLength);
				for(i = 0; i < keyLength; i++)
				{
					printf("%02x", (unsigned char)keyValue[i]);
				}
				printf("\n");
			}

			TrustKeystore_MemFree((void**)&keyValue);
		}
		break;
	case 7:
		{
			printf("enter key id : ");
			scanf("%s", szInKey);

			TIME_START;

			if((nError = TrustKeystore_GetEncKeyInfo(pCtx, szInKey, &szKeyInfo)) != 0)
			{
				printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
			}
			else
			{
				printf("EncKey Info : %s\n", szKeyInfo);
			}
			TrustKeystore_MemFree((void**)&szKeyInfo);
		}
		break;
	case 8:
		{
			char szAll[256] = {0};
			printf("update all key?(y/n)");
			while(scanf("%s", szAll))
			{
				if(strncmp(szAll, "y", sizeof(szAll)-1) == 0)
				{
					memset(szInKey, 0x00, sizeof(szInKey));
					break;
				}
				else if(strncmp(szAll, "n", sizeof(szAll)-1) == 0)
				{
					printf("\nenter key id list : ");
					scanf("%s", szInKey);
					break;
				}
			}			

			TIME_START;

			if((nError = TrustKeystore_UpdateKey(pCtx, szInKey)) != 0)
			{
				printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
			}
			else
				printf("Update Success\n");
		}
		break;

	case 9:
		{
			TrustKeystore_MemFree((void**)&EncText);

			printf("enter key id : ");
			scanf("%s", szInKey);
			getchar();
			printf("enter text for encrypt : ");		
			scanf("%[^\n]s", szPlainText);
				
			TIME_START;

			if((nError = TrustKeystore_Encrypt(pCtx, szInKey, szPlainText, strlen(szPlainText), &EncText, &EncLen)) != 0)
			{
				printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
			}
			else
			{
				printf("EncText[%d] : ", EncLen);
				for(i = 0; i < EncLen; i++)
				{
					printf("%02x", (unsigned char)EncText[i]);
				}
				printf("\n");
			}
		}
		break;

	case 10:

		if((nError = TrustKeystore_Decrypt(pCtx, szInKey, EncText, EncLen, &DecText, &DecLen)) != 0)
		{
			printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
		}
		else
		{
			printf("DecText[%d] : %0.*s\n", DecLen, DecLen, DecText);
		}

		TrustKeystore_MemFree((void**)&EncText);
		TrustKeystore_MemFree((void**)&DecText);

		break;
#endif
	case 11:
		{
#if defined (TEST_TKS_AGENT) || defined (TEST_TKS_AGENT_ADV) || defined (TEST_TKS_AGENT_LITE)
			printf("This fuction is supported in TrustKeystoreAgent.dll\n");
#else
			while(1)
			{
				int nIndMenu = 0;

				printf("\n");
				printf("1. call TrustKeystore_Indirect_MakeRequestKeyMsg()\n");
				printf("2. call TrustKeystore_Indirect_MakeResponseKeyMsg()\n");
				printf("3. call TrustKeystore_Indirect_SetKey()\n");
				printf("4. call TrustKeystore_Indirect_GetKey()\n");
				printf("0. return top menu\n");
				printf(": ");

				scanf("%d", &nIndMenu);

				switch(nIndMenu)
				{
				case 1:
					TrustKeystore_MemFree((void**)&reqMsg);
					if((nError = TrustKeystore_Indirect_MakeRequestKeyMsg(pCtx, szDeviceID2, szKeyID_Ind, &reqMsg, &reqMsgLen)) != 0)
					{
						printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
						break;
					}
					else
					{
						printf("TrustKeystore_Indirect_MakeRequestKeyMsg Success\n");
						printf("Device Id : %s\n", szDeviceID2);
						printf("Key Id : %s\n", szKeyID_Ind);
						printf("Req Msg[%d] : ", reqMsgLen);
						for(i = 0; i < reqMsgLen; i++)
						{
							printf("%02x", (unsigned char)reqMsg[i]);
						}
						printf("\n");
					}
					break;
				case 2:
					TrustKeystore_MemFree((void**)&resMsg);
					if((nError = TrustKeystore_Indirect_MakeResponseKeyMsg(pCtx, szDeviceID1, reqMsg, reqMsgLen, &resMsg, &resMsgLen)) != 0)
					{
						printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
						break;
					}
					else
					{
						printf("TrustKeystore_Indirect_MakeResponseKeyMsg Success\n");
						printf("Device Id : %s\n", szDeviceID1);
						printf("Res Msg[%d] : ", resMsgLen);
						for(i = 0; i < resMsgLen; i++)
						{
							printf("%02x", (unsigned char)resMsg[i]);
						}
						printf("\n");
					}
					break;
				case 3:
					if((nError = TrustKeystore_Indirect_SetKey(pCtx, resMsg, resMsgLen)) != 0)
					{
						printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
						break;
					}
					else
						printf("TrustKeystore_Indirect_SetKey Success\n");

					break;
				case 4:
					TrustKeystore_MemFree((void**)&keyValue);
					if((nError = TrustKeystore_Indirect_GetKey(pCtx, szKeyID_Ind, &keyValue, &keyLength)) != 0)
					{
						printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
						break;
					}
					else
					{
						printf("Key Id : %s\n", szKeyID_Ind);
						printf("Key[%d] : ", keyLength);
						for(i = 0; i < keyLength; i++)
						{
							printf("%02x", (unsigned char)keyValue[i]);
						}
						printf("\n");
					}
					break;
				}

				if(nIndMenu == 0)
				{
					TrustKeystore_MemFree((void**)&reqMsg);
					TrustKeystore_MemFree((void**)&resMsg);
					TrustKeystore_MemFree((void**)&keyValue);

					break;
				}				
			}
#endif
		}

		break;
#ifndef TEST_TKS_AGENT_LITE
	case 12:
		TrustKeystore_Final(&pCtx);
		break;

	case 22:	// 무한 키 요청
		
		for(j = 0; ; j++)
		{
			
// 			TIME(ntime);
// 			if(ntime >= 60 * 1000)	// 1분
// 			{
// 				printf("Key Count : %d\n", j);
// 				break;
// 			}

			if((nError = TrustKeystore_Init(&pCtx, szConfPath)) != 0)
			{
				printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
				break;
			}

			if((nError = TrustKeystore_GetKey(pCtx, szKeyID_enc, &keyValue, &keyLength)) != 0)
			{
				printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
				if(nError == -5411)
					break;
			}
			else
			{
				printf("Key[%d] : ", keyLength);
				for(i = 0; i < keyLength; i++)
				{
					printf("%02x", (unsigned char)keyValue[i]);
				}
				printf("\n");
			}
			TrustKeystore_MemFree((void**)&keyValue);

			TrustKeystore_Final(&pCtx);
		}
		break;
	case 33:
		if((nError = TrustKeystore_Init(&pCtx, szConfPath)) != 0)
		{
			printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));			
		}
		while(1)
		{
			if((nError = TrustKeystore_GetKey(pCtx, szKeyID_d, &keyValue, &keyLength)) != 0)
			{
				printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
				if(nError == -5411)
					break;
			}
			else
			{
				printf("Key[%d] : ", keyLength);
				for(i = 0; i < keyLength; i++)
				{
					printf("%02x", (unsigned char)keyValue[i]);
				}
				printf("\n");
			}
			TrustKeystore_MemFree((void**)&keyValue);
		}
		break;
#endif

#if 0
	case 12:
		{
			char szKeyIV[] = "0123456789abcde)!@#$%^&*(ABCDE";
			char szPlainText[] = "asdfqwer1234567890한글1234!@#$샾";
			char *pEncData = NULL, *pDecData = NULL;
			int nEncLen = 0, nDecLen = 0;

			if((nError = TrustKeystore_Aes128Cbc_Encrypt(&pEncData, &nEncLen, szPlainText, strlen(szPlainText), szKeyIV)) != 0)
			{
				printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
				break;
			}
			else
			{
				printf("PlainText : %s\n", szPlainText);
				printf("EncData[%d] : ", nEncLen);
				for(i = 0; i < nEncLen; i++)
				{
					printf("%02x", (unsigned char)pEncData[i]);
				}
				printf("\n");
			}
			if((nError = TrustKeystore_Aes128Cbc_Decrypt(&pDecData, &nDecLen, pEncData, nEncLen, szKeyIV)) != 0)
			{
				printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
				break;
			}
			else
			{

				printf("DecText : %s\n", pDecData);
			}
		}
		
		break;
	case 13:
		{
			char szPlainText[] = "asdfqwer1234567890한글1234!@#$샾";
			char sha256Data[32] = {0};
			char *pEncData = NULL, *pDecData = NULL;
			int nEncLen = 0, nDecLen = 0;

			if((nError = TrustKeystore_Sha256Hash(szPlainText, strlen(szPlainText), sha256Data)) != 0)
			{
				printf("Error[%d] : %s\n", nError, TrustKeystore_GetErrorStr(nError));
				break;
			}
			else
			{
				printf("PlainText : %s\n", szPlainText);
				printf("sha256Data[%d] : ", sizeof(sha256Data));
				for(i = 0; i < sizeof(sha256Data); i++)
				{
					printf("%02x", (unsigned char)sha256Data[i]);
				}
				printf("\n");
			}
		}		
		break;
#endif
	default:
		nRet = -1;
		break;
	}
	TIME_END;

	return nRet;
}
int main(int argc, char* argv[])
{
	int nRet = 0;
#if 1
	printf("******************************************************\n");
	printf("TrustKeystoreAgent Test Start.\n");
	
	while (nRet == 0)
	{
		menu();
		//nRet = getchar();
		scanf("%d", &nRet);

		nRet = test(nRet);
	}

#else
	// 동적 로딩
#ifdef WIN32
	HINSTANCE hTrustKeystoreAgent = LoadLibrary(_T("TrustKeystoreAgent.dll"));

	if(pTrustKeystore_Init = P_TK_INIT GetProcAddress(hTrustKeystoreAgent, "TrustKeystore_Init"))	
	{
		nRet = pTrustKeystore_Init(&pCtx, szConfPath);		
	}

	if(pTrustKeystore_GetKey = P_TK_GETKEY GetProcAddress(hTrustKeystoreAgent, "TrustKeystore_GetKey"))
	{
		nRet = pTrustKeystore_GetKey(pCtx, szKeyID, &keyValue, &keyLength);
	}

	if(pTrustKeystore_GetKey = P_TK_GETKEY GetProcAddress(hTrustKeystoreAgent, "TrustKeystore_MemFree"))
	{
		pTrustKeystore_MemFree(keyValue);
	}

	FreeLibrary(hTrustKeystoreAgent);
#else
#endif

#endif

	return 0;
}

