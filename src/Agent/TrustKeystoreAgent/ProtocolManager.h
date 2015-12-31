#ifndef PROTOCOLMANAGER_H
#define PROTOCOLMANAGER_H

#ifndef NO_XML
	#define XML_STATIC
	#include "../libexpat/expat.h"
#endif

#include "util.h"

enum CheckHTTPContent
{
	CHECKHTTP_GOT_ALL_DATA,
	CHECKHTTP_RECV_DATA_REQUIER,
	CHECKHTTP_NO_DATA
};

//int KM_MakeRequest(Agent_Ctx *pContext, int nOPCode, char* szArg, char** szRequest);

int TK_ParseResponse(char* szResponse, OP_RESPONSE *pResponse);
#ifndef NO_XML
int ParseXml(const char* szXML, Parser_PARAM *pParam);
#else
int ParseNoXml(char* szNoXML, Parser_PARAM *pParam);
#endif
int TK_Indirect_MakeTLV(int nTag, char* value, int lenth, UString *pusTLV);
int TK_Indirect_PaseTLV(int nTag, char* TLV, int TLVlen, UString *pusValue);

#endif
