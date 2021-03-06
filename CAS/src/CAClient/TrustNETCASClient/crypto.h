#ifndef CRYPTO_H
#define CRYPTO_H


#include "SSLSettings.h"
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
// #include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/pem.h>


#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>



#ifndef WIN32
	#define _stricmp	strcasecmp
#endif

#define BASE64ENCODESIZE(x)		((x)+3)/3*4 + 1
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

typedef struct _UString 
{
	int	length;
	unsigned char *value;
} UString;


int makeHMAC(int nAlgo, UString *pKey, UString *pInfo, UString *pOut);
int digestSha256(UString *pusIn, UString *pusOut);
int base64Encoding(UString *f, char **t);

int makeCSR(char *szDN, char *szkeyAlgo, int keyLength, char * szPass, char **szCSR, char **szPemPriKey);
int verifyCert(char *szPemCert);

int setSubject(CertName *subject, char *szDN);

int setUString(UString *pUS, char* value, int length);
void freeUString(UString *pUS);

#endif