#include "util.h"

// for base64
#define CSP_BASE64ENCODESIZE(x)		((x)+3)/3*4 + 1
#define conv_bin2ascii(a)	(data_bin2ascii[(a)&0x3f])
#define conv_ascii2bin(a)	(data_ascii2bin[(a)&0x7f])

#define B64_EOLN		0xF0
#define B64_CR			0xF1
#define B64_EOF			0xF2
#define B64_WS			0xE0
#define B64_ERROR       	0xFF
#define B64_NOT_BASE64(a)	(((a)|0x13) == 0xF3)

static unsigned char data_bin2ascii[65]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static unsigned char data_ascii2bin[128]={
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xE0,0xF0,0xFF,0xFF,0xF1,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xE0,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0x3E,0xFF,0xF2,0xFF,0x3F,
	0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,
	0x3C,0x3D,0xFF,0xFF,0xFF,0x00,0xFF,0xFF,
	0xFF,0x00,0x01,0x02,0x03,0x04,0x05,0x06,
	0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
	0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,
	0x17,0x18,0x19,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,
	0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
	0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,
	0x31,0x32,0x33,0xFF,0xFF,0xFF,0xFF,0xFF,
};

void * TK_MemAlloc(size_t size)
{
	char *pRet = NULL;
	size_t *pSize = NULL;

	if(size > 0)
	{
		pRet = (char*)calloc(1, size + sizeof(size_t));

		if(pRet == NULL)
			goto error;

		pSize = (size_t*)pRet;
		*pSize = size;		

		pRet += sizeof(size_t);
	}

error:
	return (void*)pRet;
}

size_t TK_MemSize(void* pMem)
{
	size_t size = 0;

	if(pMem != NULL)
		size = *((size_t*)((char*)pMem - sizeof(size_t)));

	return size;
}

void * TK_ReAlloc(void *pPreMemory, size_t size)
{
	void *pRet = NULL;
	size_t nPreSize = 0;

	if(pPreMemory == NULL)
	{
		pRet = TK_MemAlloc(size);
	}
	else if(size > (nPreSize = TK_MemSize(pPreMemory)))
	{
		if((pRet = TK_MemAlloc(size)) == NULL)		
			goto error;

		memcpy(pRet, pPreMemory, nPreSize);
		TK_MemFree((void**)&pPreMemory);
	}
	else
	{
		pRet = pPreMemory;
	}

error:
	return pRet;
}

void TK_MemFree(void** ppMem)
{
	if(*ppMem)
	{
		free((void*)((char*)*ppMem-sizeof(size_t)));
		*ppMem = NULL;
	}
}

int TK_Base64_Encode(UString *f, char **t)
{
	int nRet = 0;
	int i = 0;
	unsigned long l = 0;
	int outlen = CSP_BASE64ENCODESIZE(f->length);
	unsigned char *address ;
	unsigned char * psrc = f->value;

	if((*t = (char *)TK_MemAlloc(outlen)) == NULL)	
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
		goto error;
	}

	address = (unsigned char *)*t;

	for (i = f->length; i > 0; i -= 3)
	{
		if (i >= 3)
		{
			l=	(((unsigned long)psrc[0])<<16L)|
				(((unsigned long)psrc[1])<< 8L)|psrc[2];
			*((*t)++)=conv_bin2ascii(l>>18L);
			*((*t)++)=conv_bin2ascii(l>>12L);
			*((*t)++)=conv_bin2ascii(l>> 6L);
			*((*t)++)=conv_bin2ascii(l     );

			psrc += 3;
		}
		else
		{
			l=((unsigned long)psrc[0])<<16L;
			if (i == 2) l|=((unsigned long)psrc[1]<<8L);

			*((*t)++)=conv_bin2ascii(l>>18L);
			*((*t)++)=conv_bin2ascii(l>>12L);
			*((*t)++)=(i == 1)?'=':conv_bin2ascii(l>> 6L);
			*((*t)++)='=';
		}
	}

	**t= '\0' ;
	*t = (char *)address;

error:

	return nRet;
}

int TK_Base64_Decode( char *f, UString *t)
{
	int nRet = 0;
	int i,a,b,c,d;
	unsigned long l;
	int nEqual = 0;
	int n = strlen(f)  ;
	unsigned char *address = NULL;

// 	char *equal = f;
// 	equal = strchr((char *)f,'=');
	char *equal = strchr((char *)f,'=');	

	#if defined(WIN32)
		if (equal != NULL) nEqual = n -(equal - f) ;
	#else
		if (equal != NULL) nEqual = n - (strlen(f) - strlen(equal));
	#endif

	if ((n == 0) || (n % 4 != 0) || (nEqual > 2) || ((int)strcspn(f, "`~!@#$%^&*()-_\\|[]{};:'\"?<>,. ") != n)) 
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FALIED_BASE64DECODE;
		goto error;
	}

	t->length  = 0;
	t->value = (unsigned char *)TK_MemAlloc(n);
	if(t->value == NULL)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FALIED_BASE64DECODE;
		goto error;
	}
	address = t->value ;

	/* trim white space from the start of the line. */
	while ((conv_ascii2bin(*f) == B64_WS) && (n > 0))
	{
		f++;
		n--;
	}

	/* strip off stuff at the end of the line
	 * ascii2bin values B64_WS, B64_EOLN, B64_EOLN and B64_EOF */
	while ((n > 3) && (B64_NOT_BASE64(conv_ascii2bin(f[n-1]))))
		n--;

	for (i=0; i<n; i+=4)
	{
		a=conv_ascii2bin(*(f++));
		b=conv_ascii2bin(*(f++));
		c=conv_ascii2bin(*(f++));
		d=conv_ascii2bin(*(f++));
		if ((a & 0x80) || (b & 0x80) ||	(c & 0x80) || (d & 0x80))
		{
			nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FALIED_BASE64DECODE;
			goto error;
		}

		l=(	(((unsigned long)a)<<18L)|
			(((unsigned long)b)<<12L)|
			(((unsigned long)c)<< 6L)|
			(((unsigned long)d)     ));
		*(address++)=(unsigned char)(l>>16L)&0xff;
		*(address++)=(unsigned char)(l>> 8L)&0xff;
		*(address++)=(unsigned char)(l     )&0xff;
		
		t->length  += 3;
	}

	t->length  = t->length  - nEqual;

error:

	return nRet;
}

char * TK_BIN2STR(char *pBin, int nLen)
{
	int i = 0;
	char *pRet = NULL;

	if(pBin == NULL || nLen < 1)
	{
		g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_BIN2STR;
		goto error;
	}

	if((pRet = (char*)TK_MemAlloc(nLen*2 +1)) == NULL)
	{
		g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
		goto error;
	}

	for(i=0; i<nLen; i++)
	{
		sprintf(pRet+i*2, "%02x", (unsigned char)pBin[i]);
	}

error:

	return pRet;
}

int TK_Set_UString(UString *pUS, char* value, int length)
{
	int nRet = 0;

	if(pUS == NULL || length == 0)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_SETUSTRING;
		goto error;
	}

	if((pUS->value = (unsigned char*)TK_MemAlloc(length + 1)) == NULL)	// +1 for string
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_MEMALLOC;
		goto error;
	}
	pUS->length = length;

	if(value != NULL)
		memcpy(pUS->value, value, length);	

error:
	return nRet;	
}

void TK_Free_UString(UString *pUS)
{
	if(pUS != NULL)
	{
		TK_MemFree((void**)&pUS->value);
		pUS->length = 0;
	}
}
// 토큰이 연속해서 있을 경우 제로사이즈 스트링으로 추출 가능하도록 하는 함수.
// (strtok는 토큰이 연속으로 있을 경우 하나의 토큰으로 처리하기 때문에.)
char * TK_Tokenizer(char *pStr, char *pDeli)
{
	int i, j, bFind = 0;
	int nCurrPtrLen = 0, nDeliLen = 0;
	static char *pCurrPtr = NULL;
	static int bEof = 0;
	
	if(pStr != NULL)
	{
		pCurrPtr = pStr;
		bEof = 0;
	}
	else if(bEof)
	{
		return NULL;
	}
	else
	{
		pCurrPtr = pCurrPtr + strlen(pCurrPtr) + 1;
	}

	nCurrPtrLen = strlen(pCurrPtr);
	nDeliLen = strlen(pDeli);

	// tokenizing
	for(i = 0; i < nCurrPtrLen; i++)
	{
		for(j = 0; j < nDeliLen; j++)
		{
			if(pCurrPtr[i] == pDeli[j])
			{
				pCurrPtr[i] = '\0';
				bFind = 1;
				break;
			}
		}

		if(bFind)
			break;
	}

	if(!bFind)
		bEof = 1;		

	return pCurrPtr;
}
