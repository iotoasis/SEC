#ifndef _SEED256_H
#define _SEED256_H

/********************** Include files ************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "type.h"

/********************* Type Definitions **********************/
/*
#ifndef TYPE_DEFINITION
    #define TYPE_DEFINITION
    #if defined(__alpha)
        typedef unsigned int        DWORD;
        typedef unsigned short      WORD;
    #else
        typedef unsigned long int   DWORD;
        typedef unsigned short int  WORD;
    #endif
    typedef unsigned char           BYTE;
#endif
*/
/***************************** Endianness Define **************/
// If endianness is not defined correctly, you must modify here.
// SEED uses the Little endian as a defalut order

/*
#if __alpha__   ||      __alpha ||      __i386__        ||      i386    ||      _M_I86  ||      _M_IX86 ||      \
        __OS2__         ||      sun386  ||      __TURBOC__      ||      vax             ||      vms             ||      VMS             ||      __VMS
#define SEED_LITTLE_ENDIAN
#else
#define SEED_BIG_ENDIAN
#endif
*/

/******************* Constant Definitions *********************/

#define NoRounds         24
#define NoRoundKeys      (NoRounds*2)
#define SeedBlockSize    16    /* in bytes */
#define SeedBlockLen     128   /* in bits */

/********************** Common Macros ************************/
#if defined(_MSC_VER) && !defined(_M_IA64)
# define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
# define GETU32(p) SWAP(*((U32 *)(p)))
# define PUTU32(ct, st) { *((U32 *)(ct)) = SWAP((st)); }
#else
# define GETU32(pt) (((U32)(pt)[0] << 24) ^ ((U32)(pt)[1] << 16) ^ ((U32)(pt)[2] <<  8) ^ ((U32)(pt)[3]))
# define PUTU32(ct, st) { (ct)[0] = (U8)((st) >> 24); (ct)[1] = (U8)((st) >> 16); (ct)[2] = (U8)((st) >>  8); (ct)[3] = (U8)(st); }
#endif

#if defined(_MSC_VER)
    #define ROTL(x, n)     (_lrotl((x), (n)))
    #define ROTR(x, n)     (_lrotr((x), (n)))
#else
    #define ROTL(x, n)     (((x) << (n)) | ((x) >> (32-(n))))
    #define ROTR(x, n)     (((x) >> (n)) | ((x) << (32-(n))))
#endif


/**************** Function Prototype Declarations **************/
typedef struct seed256_key_struct
{
	U32 data[48];
} SEED256_KEY;

void S_SEED256_Encrypt(U8 *pbData, SEED256_KEY *key);
void S_SEED256_Decrypt(U8 *pbData, SEED256_KEY *key);
void S_SEED256_KeySchedule(SEED256_KEY *key, U8 *pbUserKey);

void S_SEED256_ECB_Encrypt(U8 *in, U8 *out, SEED256_KEY *key, long bytes);
void S_SEED256_ECB_Decrypt(U8 *in, U8 *out, SEED256_KEY *key, long bytes);

void S_SEED256_CBC_Encrypt(U8 *in, U8 *out, SEED256_KEY *key, long bytes, U8 *iv);
void S_SEED256_CBC_Decrypt(U8 *in, U8 *out, SEED256_KEY *key, long bytes, U8 *iv);

void S_SEED256_CFB_Encrypt(U8 *in, U8 *out, SEED256_KEY *key, int *numbits, long bytes, U8 *iv);
void S_SEED256_CFB_Decrypt(U8 *in, U8 *out, SEED256_KEY *key, int *numbits, long bytes, U8 *iv);

void S_SEED256_OFB_Encrypt(U8 *in, U8 *out, SEED256_KEY *key, int *numbits, long bytes, U8 *iv);
void S_SEED256_OFB_Decrypt(U8 *in, U8 *out, SEED256_KEY *key, int *numbits, long bytes, U8 *iv);

void S_SEED256_CTR128_Encrypt(U8 *in, U8 *out, U32 length, SEED256_KEY *key, U8 ivec[SeedBlockSize], U8 ecount_buf[SeedBlockSize], unsigned int *num);
void S_SEED256_CTR128_Decrypt(U8 *in, U8 *out, U32 length, SEED256_KEY *key, U8 ivec[SeedBlockSize], U8 ecount_buf[SeedBlockSize], unsigned int *num);

/*************************** END OF FILE **************************************/
#endif
