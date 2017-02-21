#ifndef TRUSTNETCASCLIENT_H
#define TRUSTNETCASCLIENT_H

#define SIGN_TEST	// 테스트 용도.

#if defined (WIN32)
	#if defined (TRUSTNETCASCLIENT_EXPORTS)
		#define TRUSTNETCASCLIENT_API __declspec(dllexport)
	#else
		#define TRUSTNETCASCLIENT_API __declspec(dllimport)
	#endif
#elif defined(LINUX) || (linux) || (AIX)
//  GCC
	#if defined (TRUSTNETCASCLIENT_EXPORTS)
		#define TRUSTNETCASCLIENT_API __attribute__((visibility("default")))
	#else
		#define TRUSTNETCASCLIENT_API
	#endif
#else
	#define TRUSTNETCASCLIENT_API
#endif

#define CERT_ISSUE		0
#define CERT_REISSUE	1

#ifdef __cplusplus
extern "C" {
#endif
	TRUSTNETCASCLIENT_API int TrustNet_Init(void **ppContext, char * szConfPath);
	TRUSTNETCASCLIENT_API int TrustNet_IssueDeviceCert(void *pContext, char *szDevId, int nReIssue);
	TRUSTNETCASCLIENT_API int TrustNet_GetDeviceCert(void *pContext, char *szDevId, char **ppCert);
	TRUSTNETCASCLIENT_API int TrustNet_GetDevicePrikeyAndPass(void *pContext, char *szDevId, char **ppPriKey, char **ppPass);
	TRUSTNETCASCLIENT_API int TrustNet_GetAuthKeyFromMEF(void *pContext, char *szDevId, char *szSignSrc, char *szSignValue, char **ppAuthKey);
	TRUSTNETCASCLIENT_API int TrustNet_Final(void **ppContext);

	// test
#ifdef SIGN_TEST
	TRUSTNETCASCLIENT_API int TrustNet_SignTest(char *signSrc, char *szPemPriKey, char *szPass, char **szSign);
	TRUSTNETCASCLIENT_API int TrustNet_VerifyTest(char *signSrc, char *szSign, char *szCert);
#endif
	
#ifdef __cplusplus
}
#endif


#endif