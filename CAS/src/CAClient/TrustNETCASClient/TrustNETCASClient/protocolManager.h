#ifndef PROTOCOLMANAGER_H
#define PROTOCOLMANAGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XML_STATIC
#include "../libexpat/expat.h"

typedef struct _RESPONSE {
	char *pDn;
	char *pKeyAlgo;
	char *pKeyLength;
	char *pCert;
	char *pAuthKey;
}RESPONSE;

typedef struct _Parser_PARAM {
	int     nDepth;     // depth of tag
	int		nResult;
	int		nFlag;
	RESPONSE response;
} Parser_PARAM;

// XML Parser flag
#define		ON_TRUSTNETCAS		0x00000001
#define		ON_RESULT			0x00000002
#define		ON_DN				0x00000004
#define		ON_KEYALGO			0x00000008
#define		ON_KEYLENGTH		0x00000010
#define		ON_CERT				0x00000020
#define		ON_AUTHKEY			0x00000040

#ifndef WIN32
	#define _stricmp	strcasecmp
#endif

int MakeRequest(char *szReqIP, char *szReqPort, char *szReqPage, char* szMsg, char** szRequest);
int ParseXml(const char* szXML, Parser_PARAM *pParam);
void FreeParam(Parser_PARAM *pParam);
int UriEncode(char *str, char **ppEncoded);
int UriEncodeValue(char *str, char **ppEncoded);

void XMLCALL OnElementStart(void* pParam, const XML_Char* pszName, const XML_Char* rgpszAttr[]);
void XMLCALL OnElementEnd(void* pParam, const XML_Char* pszName);
void XMLCALL OnElementContents(void* pParam, const XML_Char* pContents, int nLen);

#endif