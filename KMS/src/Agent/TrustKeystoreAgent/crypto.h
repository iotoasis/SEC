#ifndef CRYPTO_H
#define CRYPTO_H

#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include "util.h"

// crypt
int TK_Aes128_Encrypt(UString *pOut, UString *pIn, UString *pKeyIV);
int TK_Aes128_Decrypt(UString *pOut, UString *pIn, UString *pKeyIV);
int TK_Make_Random(char* rand, int nLen);
int TK_Make_HMAC(int nAlgo, UString *pKey, UString *pInfo, UString *pOut);
int TK_Sha256Hash(UString *pusIn, UString *pusOut);



#endif
