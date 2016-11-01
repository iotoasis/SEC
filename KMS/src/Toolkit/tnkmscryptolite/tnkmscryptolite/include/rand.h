#ifndef _RAND_H_
#define _RAND_H_

#include "type.h"

#ifdef __cplusplus
extern "C"
{
#endif

/////////////////////////////////////////////////////////////////////////
typedef struct _KL_ATTRIBUTE {
	U32		type;			/* 데이터의 타입				*/
	void	*pValue;			/* 데이터						*/
	U32		ulValueLen;		/* 데이터의 byte 단위 크기		*/
	int	bSensitive;		/* 보안상 민감한 데이터 여부	*/
	int	bAlloc;			/* pValue에 대한 라이브러리
									   내부에서의 메모리 할당 여부	*/
} KL_ATTRIBUTE, *KL_ATTRIBUTE_PTR;

#define	KL_SZ_OBJECT			8		
typedef KL_ATTRIBUTE			KL_OBJECT[KL_SZ_OBJECT];
typedef KL_OBJECT*				KL_OBJECT_PTR;

#define	KL_SZ_CONTEXT_INTERNAL	10
#define	KL_SZ_CONTEXT_EXTERNAL	10
#define	KL_SZ_CONTEXT	KL_SZ_CONTEXT_INTERNAL+KL_SZ_CONTEXT_EXTERNAL

typedef KL_ATTRIBUTE	KL_CONTEXT[KL_SZ_CONTEXT];
typedef KL_CONTEXT*		KL_CONTEXT_PTR;
/////////////////////////////////////////////////////////////////////////

/* mode */
#define DRBG_RAND_SHA256 2
#define DRBG_RAND_SHA512 3

void S_RAND_Bytes(U8 *buf, int num);
void S_GenerateRandom_LSH256(U8 *out, U32 bytes);
void S_GenerateRandom(U8 *out, U32 bytes, int mode);

#ifdef __cplusplus
}
#endif

#endif
