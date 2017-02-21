#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
	#include <direct.h>
#endif


int MakeDirRecursive(char *szFullPath);
int ReadTxtFile(char *szFilePath, char **ppReadBuf);
int WriteTxtFile(char *szFilePath, char *pWriteBuf);

#endif