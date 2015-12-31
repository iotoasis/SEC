#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "TK_Config.h"
#include "TK_Error.h"

void * TK_MemAlloc(size_t size);
size_t TK_MemSize(void* pMem);
void * TK_ReAlloc(void *pPreMemory, size_t size);
void TK_MemFree(void** ppMem);

int TK_Base64_Encode(UString *f, char **t);
int TK_Base64_Decode(char *f, UString *t);
char * TK_BIN2STR(char *pBin, int nLen);

int TK_Set_UString(UString *pUS, char* value, int length);
void TK_Free_UString(UString *pUS);

char * TK_Tokenizer(char *pStr, char *pDeli);

#endif
