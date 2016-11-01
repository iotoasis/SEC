/*
 error.h : 
 created by dgshin, in 2012/10/26

 함수 return type의 정의, 실패여부 검증등 
  파일단위 에러타입등을 정의 
*/

#ifndef __ERROR_H__
#define __ERROR_H__


#ifdef __cplusplus
extern "C"
{
#endif

typedef  int SRESULT;

/*성공여부.. 1st byte */
#define S_SUCCESS	0x00000000
#define S_FAILED    0xF0000000

/* 대분류.. 2-3nd byte */

/* CryptoLib */
#define SL_BIGNUM	0x00100000
#define SL_BLOCK	0x00200000
#ifndef NO_ECC
#define SL_ECC		0x00300000
#endif
#define SL_HASH		0x00400000
#define SL_MAC		0x00500000
#define SL_PUBLIC	0x00600000
#define SL_RANDOM	0x00700000
#define SL_SIGN		0x00800000
#define SL_VERIFY	0x00900000

/* 발발지점 (함수단위) 4-5th byte */

/* 이유 6-8th byte */


/* status 가 S_FAILED 인지 가려내는 함수  */
#define ERROR_FAILED(status)	((SRESULT) status < 0)
#define ERROR_DETECTED(status, error) ((status & error) == error)

/* 보통 쓰여진 status 를 function library 구분 code로 만들어준다. */
#define ERROR_MKFUNC(status) ((SRESULT) status  << 12 ) & 0x000FF000
/* 보통 쓰여진 status 를 library 구분 code로 만들어 준다.  */
#define ERROR_MKLIB(status)   ((SRESULT) status  << 20 ) & 0x0FF00000

#ifdef __cplusplus
}
#endif


#endif