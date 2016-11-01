#ifndef __TRUST_KEYSTORE_CSTK_H__
#define __TRUST_KEYSTORE_CSTK_H__

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef WIN32
#ifdef TRUSTKEYSTORECSTK_EXPORTS
#define TKSCSTK_API __declspec(dllexport) 
#elif defined(TRUSTKEYSTORECSTK_IMPORTS)
#define TKSCSTK_API __declspec(dllimport) 
#else
#define TKSCSTK_API
#endif
#endif

#ifndef _USTRING
#define _USTRING
typedef struct _UString 
{
	int	length;
	unsigned char *value;
} UString;
#endif

enum TKS_CSTK_ALGO_TYPE{
	TKS_CSTK_UNDEFINED	= 0 ,	
	TKS_CSTK_DIGEST_SHA256 = 105,
	TKS_CSTK_DIGEST_SHA384    ,
	TKS_CSTK_DIGEST_SHA512    ,
	TKS_CSTK_DIGEST_SHA224    ,
	TKS_CSTK_DIGEST_LSH224    ,	
	TKS_CSTK_DIGEST_LSH256    ,
	TKS_CSTK_DIGEST_LSH384    ,
	TKS_CSTK_DIGEST_LSH512    ,

	TKS_CSTK_BLOCK_SEED_ECB = 701,
	TKS_CSTK_BLOCK_SEED_CBC      ,
	TKS_CSTK_BLOCK_SEED_CFB_64   ,
	TKS_CSTK_BLOCK_SEED_OFB      ,
	TKS_CSTK_BLOCK_SEED_CFB      ,
	TKS_CSTK_BLOCK_SEED_CTR      ,
	TKS_CSTK_BLOCK_SEED_256_ECB  ,
	TKS_CSTK_BLOCK_SEED_256_CBC  ,
	TKS_CSTK_BLOCK_SEED_256_CFB_64   ,
	TKS_CSTK_BLOCK_SEED_256_OFB  ,
	TKS_CSTK_BLOCK_SEED_256_CFB  ,
	TKS_CSTK_BLOCK_SEED_256_CTR  ,

	TKS_CSTK_BLOCK_AES_128_ECB = 1300,
	TKS_CSTK_BLOCK_AES_192_ECB       ,
	TKS_CSTK_BLOCK_AES_256_ECB       ,
	TKS_CSTK_BLOCK_AES_128_CBC       ,
	TKS_CSTK_BLOCK_AES_192_CBC       ,
	TKS_CSTK_BLOCK_AES_256_CBC       ,
	TKS_CSTK_BLOCK_AES_128_CFB       ,
	TKS_CSTK_BLOCK_AES_192_CFB       ,
	TKS_CSTK_BLOCK_AES_256_CFB       ,
	TKS_CSTK_BLOCK_AES_128_OFB       ,
	TKS_CSTK_BLOCK_AES_192_OFB       ,
	TKS_CSTK_BLOCK_AES_256_OFB       ,
	TKS_CSTK_BLOCK_AES_128_CTR       ,
	TKS_CSTK_BLOCK_AES_192_CTR       ,
	TKS_CSTK_BLOCK_AES_256_CTR       ,
	TKS_CSTK_BLOCK_AES_128_CFB1      ,
	TKS_CSTK_BLOCK_AES_192_CFB1      ,
	TKS_CSTK_BLOCK_AES_256_CFB1      ,
	TKS_CSTK_BLOCK_AES_128_CFB8      ,
	TKS_CSTK_BLOCK_AES_192_CFB8      ,
	TKS_CSTK_BLOCK_AES_256_CFB8      ,

	TKS_CSTK_BLOCK_ARIA_128_ECB = 1401,
	TKS_CSTK_BLOCK_ARIA_192_ECB       ,
	TKS_CSTK_BLOCK_ARIA_256_ECB       ,
	TKS_CSTK_BLOCK_ARIA_128_CBC       ,
	TKS_CSTK_BLOCK_ARIA_192_CBC       ,
	TKS_CSTK_BLOCK_ARIA_256_CBC       ,
	TKS_CSTK_BLOCK_ARIA_128_CFB       ,
	TKS_CSTK_BLOCK_ARIA_192_CFB       ,
	TKS_CSTK_BLOCK_ARIA_256_CFB       ,
	TKS_CSTK_BLOCK_ARIA_128_OFB       ,
	TKS_CSTK_BLOCK_ARIA_192_OFB       ,
	TKS_CSTK_BLOCK_ARIA_256_OFB       ,
	TKS_CSTK_BLOCK_ARIA_128_CTR       ,
	TKS_CSTK_BLOCK_ARIA_192_CTR       ,
	TKS_CSTK_BLOCK_ARIA_256_CTR       ,
	
	TKS_CSTK_BLOCK_LEA_128_ECB = 1501,
	TKS_CSTK_BLOCK_LEA_192_ECB       ,
	TKS_CSTK_BLOCK_LEA_256_ECB       ,
	TKS_CSTK_BLOCK_LEA_128_CBC       ,
	TKS_CSTK_BLOCK_LEA_192_CBC       ,
	TKS_CSTK_BLOCK_LEA_256_CBC       ,
	TKS_CSTK_BLOCK_LEA_128_CFB       ,
	TKS_CSTK_BLOCK_LEA_192_CFB       ,
	TKS_CSTK_BLOCK_LEA_256_CFB       ,
	TKS_CSTK_BLOCK_LEA_128_OFB       ,
	TKS_CSTK_BLOCK_LEA_192_OFB       ,
	TKS_CSTK_BLOCK_LEA_256_OFB       ,
	TKS_CSTK_BLOCK_LEA_128_CTR       ,
	TKS_CSTK_BLOCK_LEA_192_CTR       ,
	TKS_CSTK_BLOCK_LEA_256_CTR       ,	
};

/* error code : -4000 ~ -4999 */
#define TK_CSTK_SUCCESS		0
#define TK_CSTK_ERROR_CONTEXT_EMPTY_OR_WRONG			-4000
#define TK_CSTK_ERROR_CONF_PATH_EMPTY_OR_WRONG			-4001
#define TK_CSTK_ERROR_UNSUPPORTED_ALGORITHM				-4002
#define TK_CSTK_ERROR_KEYID_EMPTY_OR_WRONG				-4003
#define TK_CSTK_ERROR_TARGET_BUFFER_TOO_SMALL			-4004
#define TK_CSTK_ERROR_LIGHTWEIGHT_MODE_UNSUPPORTED_API	-4005
#define TK_CSTK_ERROR_KEY_IV_LENGTH_MISSMATCH			-4006
#define TK_CSTK_ERROR_DEVICE_MODE_UNSUPPORTED_API		-4007
#define TK_CSTK_ERROR_GATEWAY_MODE_UNSUPPORTED_API		-4008
#define TK_CSTK_ERROR_LIGHTWEIGHT_MODE_UNSUPPORTED_ALGORITHM	-4009
#define TK_CSTK_ERROR_MAKE_KEYFROMMATERIAL_ARG_EMPTY_OR_WRONG	-4010
#define TK_CSTK_ERROR_KEY_METERIAL_HASH_LENGTH_MISSMATCH		-4011
#define TK_CSTK_ERROR_TARGET_NOT_MEMORY_ALLOCATION				-4012

/* TKS CSTK Initailize & Finalize API */
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_Init(void **ppCtx, char * szConfPath);
#else
int TrustKeystoreTK_Init(void **ppCtx, char * szConfPath);
#endif
#ifdef WIN32
TKSCSTK_API void TrustKeystoreTK_Final(void **ppCtx);
#else
void TrustKeystoreTK_Final(void **ppCtx);
#endif

/* TKS CSTK Encryption & Decryption API */
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_Encipher(void *pCtx, char *szKeyID, UString *in, UString *enc);
#else
int TrustKeystoreTK_Encipher(void *pCtx, char *szKeyID, UString *in, UString *enc);
#endif
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_Decrypt(void *pCtx, char *szKeyID, UString *enc, UString *dec);
#else
int TrustKeystoreTK_Decrypt(void *pCtx, char *szKeyID, UString *enc, UString *dec);
#endif

/* TKS CSTK Msg Digest API */
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_Hash(int nHashAlgo, UString *in, UString *out);
#else
int TrustKeystoreTK_Hash(int nHashAlgo, UString *in, UString *out);
#endif

/* TKS CSTK Hash-based Msg Authentication Code API */
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_GenerateHMAC(void *pCtx, char *szKeyID, UString *in, UString *out);
#else
int TrustKeystoreTK_GenerateHMAC(void *pCtx, char *szKeyID, UString *in, UString *out);
#endif

/* TKS CSTK KeyMsg...Request & Response & Set API */
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_MakeRequestKeyMsg(void *pCtx, char *szDeviceID, char *szKeyID, UString *usRequestMsg);
#else
int TrustKeystoreTK_MakeRequestKeyMsg(void *pCtx, char *szDeviceID, char *szKeyID, UString *usRequestMsg);
#endif

#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_MakeResponseKeyMsg(void *pCtx, char *szDeviceID, UString *usRequestMsg, UString *usResponseMsg);
#else
int TrustKeystoreTK_MakeResponseKeyMsg(void *pCtx, char *szDeviceID, UString *usRequestMsg, UString *usResponseMsg);
#endif

#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_SetKey(void *pCtx, UString *usResponseMsg);
#else
int TrustKeystoreTK_SetKey(void *pCtx, UString *usResponseMsg);
#endif

#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_GetKey(void *pCtx, char *szKeyID, UString *usKeyIv);
#else
int TrustKeystoreTK_GetKey(void *pCtx, char *szKeyID, UString *usKeyIv);
#endif

/* TKS CSTK Error API */
#ifdef WIN32
TKSCSTK_API int TrustKeystoreTK_GetErrorCode(void);
#else
int TrustKeystoreTK_GetErrorCode(void);
#endif

#ifdef __cplusplus
}
#endif

#endif __TRUST_KEYSTORE_CSTK_H__