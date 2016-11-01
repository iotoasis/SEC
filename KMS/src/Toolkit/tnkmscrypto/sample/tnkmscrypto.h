#ifndef __TRUST_KMS_CRYPTO_H__
#define __TRUST_KMS_CRYPTO_H__

#ifdef __cplusplus
extern "C"
{
#endif

typedef unsigned char		TN_BYTE;
typedef TN_BYTE				TN_CHAR;
typedef TN_BYTE				TN_BBOOL;

typedef unsigned int		TN_ULONG;
typedef int					TN_LONG;
typedef unsigned short		TN_USHORT;
typedef short				TN_SHORT;

#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
#define TN_ULONG64 unsigned __int64
#elif defined(__arch64__)
#define TN_ULONG64 unsigned long
#else
#define TN_ULONG64 unsigned long long
#endif

typedef TN_BYTE				*TN_BYTE_PTR;
typedef TN_CHAR				*TN_CHAR_PTR;
typedef TN_ULONG			*TN_ULONG_PTR;
typedef void				*TN_VOID_PTR;

/***********************************************************************
	함수의 반환코드를 나타내는 자료형
***********************************************************************/
typedef TN_ULONG	TN_RV;

/***********************************************************************
	Return value
***********************************************************************/
/* return value : 성공시 */
#define TNR_OK								0

/* return value : 실패시 */
#define TNR_DEFAULT_ERROR					-1

/***********************************************************************
	함수에 사용되는 구조체
***********************************************************************/
typedef struct _TN_USTRING 
{
	TN_ULONG	length;
	unsigned char *	value;
} TN_USTRING, *TN_USTRING_PTR;

#ifdef WIN32
#ifdef TNKMSCRYPTO_EXPORTS
#define TCL_API __declspec(dllexport) 
#elif defined(TNKMSCRYPTO_IMPORTS)
#define TCL_API __declspec(dllimport) 
#else
#define TCL_API
#endif
#endif

/***********************************************************************
	알고리즘 정보
***********************************************************************/
enum TCLM_ALGO_TYPE{
	TN_UNDEFINED	= 0 ,	/* undefined nid*/
	TN_DIGEST_SHA256 = 105,
	TN_DIGEST_SHA384    ,
	TN_DIGEST_SHA512    ,
	TN_DIGEST_SHA224    ,
	TN_DIGEST_LSH224    ,	
	TN_DIGEST_LSH256    ,
	TN_DIGEST_LSH384    ,
	TN_DIGEST_LSH512    ,

	TN_BLOCK_SEED_ECB = 701,
	TN_BLOCK_SEED_CBC      ,
	TN_BLOCK_SEED_CFB_64   ,
	TN_BLOCK_SEED_OFB      ,
	TN_BLOCK_SEED_CFB      ,
	TN_BLOCK_SEED_CTR      ,
	TN_BLOCK_SEED_256_ECB  ,
	TN_BLOCK_SEED_256_CBC  ,
	TN_BLOCK_SEED_256_CFB_64   ,
	TN_BLOCK_SEED_256_OFB  ,
	TN_BLOCK_SEED_256_CFB  ,
	TN_BLOCK_SEED_256_CTR  ,

	TN_BLOCK_AES_128_ECB = 1300,
	TN_BLOCK_AES_192_ECB       ,
	TN_BLOCK_AES_256_ECB       ,
	TN_BLOCK_AES_128_CBC       ,
	TN_BLOCK_AES_192_CBC       ,
	TN_BLOCK_AES_256_CBC       ,
	TN_BLOCK_AES_128_CFB       ,
	TN_BLOCK_AES_192_CFB       ,
	TN_BLOCK_AES_256_CFB       ,
	TN_BLOCK_AES_128_OFB       ,
	TN_BLOCK_AES_192_OFB       ,
	TN_BLOCK_AES_256_OFB       ,
	TN_BLOCK_AES_128_CTR       ,
	TN_BLOCK_AES_192_CTR       ,
	TN_BLOCK_AES_256_CTR       ,
	TN_BLOCK_AES_128_CFB1      ,
	TN_BLOCK_AES_192_CFB1      ,
	TN_BLOCK_AES_256_CFB1      ,
	TN_BLOCK_AES_128_CFB8      ,
	TN_BLOCK_AES_192_CFB8      ,
	TN_BLOCK_AES_256_CFB8      ,

	TN_BLOCK_ARIA_128_ECB = 1401,
	TN_BLOCK_ARIA_192_ECB       ,
	TN_BLOCK_ARIA_256_ECB       ,
	TN_BLOCK_ARIA_128_CBC       ,
	TN_BLOCK_ARIA_192_CBC       ,
	TN_BLOCK_ARIA_256_CBC       ,
	TN_BLOCK_ARIA_128_CFB       ,
	TN_BLOCK_ARIA_192_CFB       ,
	TN_BLOCK_ARIA_256_CFB       ,
	TN_BLOCK_ARIA_128_OFB       ,
	TN_BLOCK_ARIA_192_OFB       ,
	TN_BLOCK_ARIA_256_OFB       ,
	TN_BLOCK_ARIA_128_CTR       ,
	TN_BLOCK_ARIA_192_CTR       ,
	TN_BLOCK_ARIA_256_CTR       ,
	
	TN_BLOCK_LEA_128_ECB = 1501,
	TN_BLOCK_LEA_192_ECB       ,
	TN_BLOCK_LEA_256_ECB       ,
	TN_BLOCK_LEA_128_CBC       ,
	TN_BLOCK_LEA_192_CBC       ,
	TN_BLOCK_LEA_256_CBC       ,
	TN_BLOCK_LEA_128_CFB       ,
	TN_BLOCK_LEA_192_CFB       ,
	TN_BLOCK_LEA_256_CFB       ,
	TN_BLOCK_LEA_128_OFB       ,
	TN_BLOCK_LEA_192_OFB       ,
	TN_BLOCK_LEA_256_OFB       ,
	TN_BLOCK_LEA_128_CTR       ,
	TN_BLOCK_LEA_192_CTR       ,
	TN_BLOCK_LEA_256_CTR       ,	
};

/*----------------------------------------------------------------------
	성공여부 코드 (1 byte)
----------------------------------------------------------------------*/
#define TN_SUCCESS		0x00000000
#define TN_FAILED		0xF0000000

/*----------------------------------------------------------------------
	대분류 코드 (2-3 byte)
----------------------------------------------------------------------*/
#define TNL_LIB_MANAGEMENT	0x00100000
#define TNL_BLOCK			0x00200000
#define TNL_HASH			0x00400000
#define TNL_MAC				0x00500000
#define TNL_RANDOM			0x00700000

/*----------------------------------------------------------------------
	함수 코드 (4-5 byte)
----------------------------------------------------------------------*/
/* MGNT FUNCTION (01 - 1F) */
#define TNF_LIB_GET_ERROR_CODE			0x00007000

/* BLOCK ENCRYPT, DECRYPT (40 - 4F) */
#define TNF_BLOCK_ENCRYPT				0x00048000
#define TNF_BLOCK_DECRYPT				0x00049000

/* DIGEST (50 - 5F) */
#define TNF_DIGEST						0x00055000

/* MAC (60 - 6F) */
#define TNF_HMAC						0x00062000

/* RANDOM (70 - 7F) */
#define TNF_GEN_RANDOM					0x00073000

/*----------------------------------------------------------------------
	일반 에러 코드 (6-8 byte : 000 - 0FF)
----------------------------------------------------------------------*/
#define TNR_SUCCESS								0x00000000
#define TNR_MEM_ALLOC_FAILED					0x00000001
#define TNR_MEM_DEALLOC_FAILED					0x00000002
#define TNR_FILE_IO_ERROR						0x00000003
#define TNR_ALGORITHM_NID_NOT_SUPPORTED			0x00000004
#define TNR_INPUT_VALUE_EMPTY_FAILED			0x00000005
#define TNR_INPUT_LENGTH_INVALIED				0x00000006
#define TNR_ARGUMENTS_BAD						0x00000007
#define TNR_BUFFER_TOO_SMALL_FAILED				0x0000001a
#define TNR_MEM_SECURE_ZERO_FAILED				0x0000001b
#define TNR_GET_ENTROPY_FAILED					0x0000001c
/*----------------------------------------------------------------------
	블럭 암호 에러 코드 (6-8 byte : 100 - 1FF)
----------------------------------------------------------------------*/
#define TNR_BLOCK_ALGO_NID_NOT_SUPPORTED		0x00000100
#define TNR_BLOCK_CIPHER_CTX_EMPTY_FAILED		0x00000101
#define TNR_BLOCK_CIPHER_EMPTY_FAILED			0x00000102
#define TNR_BLOCK_ENCRYPT_INIT_FAILED			0x00000103
#define TNR_BLOCK_ENCRYPT_UPDATE_FAILED			0x00000104
#define TNR_BLOCK_ENCRYPT_FINAL_FAILED			0x00000105
#define TNR_BLOCK_ENCRYPT_FINAL_CMAC_FAILED		0x00000106
#define TNR_BLOCK_DECRYPT_INIT_FAILED			0x00000107
#define TNR_BLOCK_DECRYPT_UPDATE_FAILED			0x00000108
#define TNR_BLOCK_DECRYPT_FINAL_FAILED			0x00000109
#define TNR_BLOCK_PADDING_BUFFER_LENGTH_WRONG	0x0000010a
#define TNR_BLOCK_PADDING_BLOCK_SIZE_WRONG		0x0000010b
#define TNR_BLOCK_PADDING_BIT_NUMBERS_WRONG		0x0000010c
#define TNR_BLOCK_PADDING_BIT_VALUE_WRONG		0x0000010d
#define TNR_BLOCK_DECRYPT_BLOCK_SIZE_WRONG		0x0000010e
#define TNR_BLOCK_KEY_LENGTH_SMALL_FAILED		0x0000010f
#define TNR_BLOCK_IV_LENGTH_SMALL_FAILED		0x00000110
/*----------------------------------------------------------------------
	해시 에러 코드 (6-8 byte : 300 - 3FF)
----------------------------------------------------------------------*/
#define TNR_DIGEST_TYPE_NOT_SUPPORTED			0x00000300	
#define TNR_DIGEST_MD_CTX_EMPTY_FAILED			0x00000301 
#define TNR_DIGEST_SIZE_WRONG					0x00000302
#define TNR_HASH_DIGEST_FAILED					0x00000303
#define TNR_DIGEST_INIT_FAILED					0x00000304
#define TNR_DIGEST_UPDATE_FAILED				0x00000305
#define TNR_DIGEST_FINAL_FAILED					0x00000306
/*----------------------------------------------------------------------
	메시지 인증코드 암호 에러 코드 (6-8 byte : 400 - 4FF)
----------------------------------------------------------------------*/
#define TNR_MAC_HASH_FAILED						0x00000404
#define TNR_MAC_TYPE_NOT_SUPPORTED				0x00000405
#define	TNR_MAC_HASH_VERIFY_LENGTH_FAILED		0x00000406
#define	TNR_MAC_HASH_VERIFY_VALUE_FAILED		0x00000407
/*----------------------------------------------------------------------
	랜덤 에러 코드 (6-8 byte : 600 - 6FF)
----------------------------------------------------------------------*/
#define TNR_RANDOM_ALGO_NOT_SUPPORTED			0x00000600
#define TNR_RADNOM_LENGTH_INVAILD				0x00000603

/* BLOCK */
#ifdef WIN32
TCL_API TN_RV TCL_Block_Encrypt(TN_LONG alg_nid, TN_USTRING_PTR in, TN_USTRING_PTR key, TN_USTRING_PTR iv, TN_USTRING_PTR out);
#else
TN_RV TCL_Block_Encrypt(TN_LONG alg_nid, TN_USTRING_PTR in, TN_USTRING_PTR key, TN_USTRING_PTR iv, TN_USTRING_PTR out);
#endif

#ifdef WIN32
TCL_API TN_RV TCL_Block_Decrypt(TN_LONG alg_nid, TN_USTRING_PTR in, TN_USTRING_PTR key, TN_USTRING_PTR iv, TN_USTRING_PTR out);
#else
TN_RV TCL_Block_Decrypt(TN_LONG alg_nid, TN_USTRING_PTR in, TN_USTRING_PTR key, TN_USTRING_PTR iv, TN_USTRING_PTR out);
#endif

/* HASH */
#ifdef WIN32
TCL_API TN_RV TCL_Digest(TN_LONG alg_nid, TN_USTRING_PTR in, TN_USTRING_PTR out);
#else
TN_RV TCL_Digest(TN_LONG alg_nid, TN_USTRING_PTR in, TN_USTRING_PTR out);
#endif

/* HMAC */
#ifdef WIN32
TCL_API TN_RV TCL_HMAC(TN_LONG alg_nid, TN_USTRING_PTR key, TN_USTRING_PTR in, TN_USTRING_PTR out);
#else
TN_RV TCL_HMAC(TN_LONG alg_nid, TN_USTRING_PTR key, TN_USTRING_PTR in, TN_USTRING_PTR out);
#endif

/* RANDOM */
#ifdef WIN32
TCL_API TN_RV TCL_GenerateRandom(TN_LONG bytes, TN_USTRING_PTR out);
#else
TN_RV TCL_GenerateRandom(TN_LONG bytes, TN_USTRING_PTR out);
#endif

/* ERROR */
#ifdef WIN32
TCL_API TN_LONG TCL_GetErrorCode(void);
#else
TN_LONG TCL_GetErrorCode(void);
#endif

#ifdef __cplusplus
}
#endif

#endif __TRUST_KMS_CRYPTO_H__