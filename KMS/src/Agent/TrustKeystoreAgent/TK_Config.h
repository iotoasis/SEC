#ifndef TK_CONFIG_H
#define TK_CONFIG_H

#if defined (TKSAGENTADV_EXPORTS)
	#define DIRECT_AGENT
#elif defined (TKSAGENT_EXPORTS)
	#define DIRECT_AGENT
	#define LIGHTWEIGHT_AGENT
#elif defined (TKSAGENTLITE_EXPORTS)
	#define INDIRECT_AGENT
#endif

// 경량 에이전트 모듈
#ifdef LIGHTWEIGHT_AGENT
	#define NO_KEY_DB
	#define NO_SSL
	#define NO_XML
#endif

// 간접 키 교환 전용 모듈
#ifdef INDIRECT_AGENT
	#define NO_KEY_DB
	#define NO_SSL
	#define NO_XML
#endif

// #define NO_WOLF_CRYPT

#ifndef WIN32
	#define _stricmp	strcasecmp
#endif

#define TK_SUCCESS 0
#define TK_FAIL -1

// Length Define
#define SHA_256_LEN			32
#define SHA_256_B64_LEN		44
#define SEED_128_KEY_SIZE	16
#define SEED_IV_SIZE		16
#define AES_128_KEY_SIZE	16
#define AES_IV_SIZE			16
#define MAX_PATH			260
#define KEK_MATERIAL_LEN	32
#define KEY_ID_LEN			100
#define MAX_KEY_LEN			255
#define KEY_ALGO_LEN		100
#define OPMODE_LEN			10
#define DATE_LEN			20
#define HMAC_LEN			SHA_256_B64_LEN
#define IP_LEN				40
#define PORT_LEN			5
#define AGENT_ID_LEN		50
#define AGENT_HINT_LEN		SHA_256_B64_LEN
#define INTEGRITY_LEN		SHA_256_B64_LEN
#define VERSION_LEN			10
#define ERRORMSG_LEN		255
#define UUID_LEN			128

#define IND_BLOCK_SIZE		32 // 256 bit

// prefix, postfix : 임의의 값
static char g_IND_PREFIX[] =  {	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
								0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
static char g_IND_POSTFIX[] = {	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
								0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

// Indirection TAG
#define IND_TAG_DEVICEID		0x00
#define IND_TAG_RANDOM			0x01
#define IND_TAG_ENCRANDOM		0x02
#define IND_TAG_ENCKEY			0x04
#define IND_TAG_KEYALGO			0x08
#define IND_TAG_KEYOPMODE		0x10
#define IND_TAG_KEYID			0x0F
#define IND_TAG_ERRORCODE		0xFF

// OPCode
#define OP_REQUEST_KEY			1
#define OP_REQUEST_ENCRYPT		2
#define OP_REQUEST_DECRYPT		3

#define OP_RESPONSE_KEY			1
#define OP_RESPONSE_ENCRYPT		2
#define OP_RESPONSE_DECRYPT		3

#ifdef _DEBUG
	static char *pDebugStr;
	static char *pStr;
	#define PRINT_DEBUG(msg)				pDebugStr = (char*)TK_MemAlloc(strlen(msg) + MAX_PATH);	sprintf(pDebugStr, "*** DEBUG File[%s] Line[%d] : %s\n", __FILE__, __LINE__, msg);	printf(pDebugStr);	TK_MemFree((void**)&pDebugStr);
	#define PRINT_DEBUG_BIN2STR(bin,len)	pStr = TK_BIN2STR(bin,len); PRINT_DEBUG(pStr); TK_MemFree((void**)&pStr);
#else
	#define PRINT_DEBUG(msg)
	#define PRINT_DEBUG_BIN2STR(bin,len)
#endif

typedef struct _UString 
{
	int	length;
	unsigned char *value;
} UString;

typedef struct KEY{
	char key_id[KEY_ID_LEN + 1];			// 키 아이디
	char enc_key_value[MAX_KEY_LEN];		// 키 값
	int key_size;							// 키 길이
	char key_Type[1 + 1];					// Static : S, Dynamic : D
	char key_algo[KEY_ALGO_LEN + 1];		// 키 알고리즘
	char op_mode[OPMODE_LEN + 1];			// 운영모드
	char expose_level[1 + 1];				// 키 외부 공개 단계 0:Server 전용, 1:Agent 공개, 2:Agent 외부 공개
	char valid_start[DATE_LEN + 1];			// 유효기간 시작일
	char valid_end[DATE_LEN + 1];			// 유효기간 종료일
	char key_hmac[HMAC_LEN + 1];			// 키 검증값
}Key;

// expose_level
#define USE_KEY_SERVER_ONLY		0
#define USE_KEY_IN_AGENT		1
#define USE_KEY_OUT_OF_AGENT	2

// Name
#define KEY_DB_FILE_NAME			"trustkeystore.keydb"
#define SSL_SERVER_CA_CERT_NAME		"unetsystem-rootca.pem"
#define IP_PADDING					"34u98fnkndfaj934932#$fjk443fdvma"
#define KMS_REQPAGE					"/getKeyInfos.tks"


typedef struct KEYLIST{
	int		nKeyCount;		// 키 개수
	Key*	pKey;			// 키 구조체 포인터
}KeyList;

typedef struct CONFIG{
	char kmsIP[IP_LEN + 1];
	char kmsPort[PORT_LEN + 1];
	char agentID[AGENT_ID_LEN + 1];
	char agentType[1 + 1];
	char agentHint[AGENT_HINT_LEN + 1];
	char Integrity[INTEGRITY_LEN + 1];
	char agentIP[IP_LEN + 1];
	char agentHMAC[HMAC_LEN + 1];
	char agentVersion[VERSION_LEN + 1];
	char agentHomeDir[MAX_PATH];
}Config;

typedef struct INDIRECTION_INFO{
	char R_ID[AGENT_ID_LEN+1];
	char r2[IND_BLOCK_SIZE];
	char key_id[KEY_ID_LEN + 1];
}Indirection_Info;

typedef struct AGENT_CTX{
	KeyList*			pKeyList;						// 암호화된 키 리스트
	Config*				pConfig;						// 설정파일 내용
	char				kekMaterial[KEK_MATERIAL_LEN];	// KEK의 Key Material
	Indirection_Info	indirectionInfo;
	void*				sslCtx;
}Agent_Ctx;

typedef union _OP_RESPONSE
{
	KeyList keyList;
	char *pszText;
}OP_RESPONSE;

typedef struct _Parser_PARAM
{
	int     nDepth;     // depth of tag
	int		nOPCode;
	int		nResult;
	int		nFlag;
	OP_RESPONSE response;	
} Parser_PARAM;

// XML Parser flag
#define		ON_TRUSTKEYSTORE	0x00000001
#define		ON_OPCODE			0x00000002
#define		ON_RESULT			0x00000004
#define		ON_KEYSTRUCT		0x00000008
#define		ON_KEYID			0x00000010
#define		ON_KEYVALUE			0x00000020
#define		ON_KEY_TYPE			0x00000040
#define		ON_KEYALGO			0x00000080
#define		ON_OPMODE			0x00000100
#define		ON_EXPOSELEVEL		0x00000200
#define		ON_VALIDSTART		0x00000400
#define		ON_VALIDEND			0x00000800
#define		ON_KEYHMAC			0x00001000
#define		ON_ENCTEXT			0x00002000
#define		ON_DECTEXT			0x00004000
#define		ON_ERRORMESSAGE		0x00008000

// Protocol Version
#define TK_PROTOCOL_VERSION 1

#endif // TK_CONFIG_H
