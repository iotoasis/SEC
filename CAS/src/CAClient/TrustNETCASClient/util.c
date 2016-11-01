#include "util.h"

char* strchrs(char *str, char *seps, char *selected)
{
	char *pRet = NULL;
	unsigned int i = 0;

	for(i = 0; i < strlen(seps); i++)
	{
		*selected = '\0';
		pRet = strchr(str, seps[i]);
		if(pRet)
		{
			*selected = seps[i];
			break;
		}
	}

	return pRet;
}

int MakeDirRecursive(char *szFullPath)
{
	int nRet = 0;
	char *pTempPath = NULL, *sp = NULL;
	char szDirSeps[] = "/\\";
	char cCurSep = '\0';
	if(szFullPath == NULL)
	{
		nRet = 0;
		goto err;
	}

	pTempPath = (char*)calloc(strlen(szFullPath) + 1, 1);
	strcpy(pTempPath, szFullPath);

	sp = pTempPath;

	while((sp = strchrs(sp, szDirSeps, &cCurSep)))
	{
		if(sp > pTempPath && *(sp - 1) != ':')
		{
			// 루트디렉토리가 아니면
			*sp = '\0';
#ifdef WIN32
			nRet = _mkdir(pTempPath);
#else
			mkdir(pTempPath, 0777);
#endif
			*sp = cCurSep;
		}
		sp++;
	}

err:
	return nRet;
}

int ReadTxtFile(char *szFilePath, char **ppReadBuf)
{
	int nRet = 0;
	int nTotalCount = 0;
	char readBuf[4096] = {0};
	FILE *fpFile = NULL;

	if(szFilePath == NULL || strlen(szFilePath) < 1 || ppReadBuf == NULL || *ppReadBuf != NULL)
	{
		nRet = -1;
		goto err;
	}

	if((fpFile = fopen(szFilePath, "r")) == NULL)
	{
		nRet = -1;
		goto err;
	}

	while( !feof(fpFile) )
	{
		int count = fread( readBuf, sizeof(char), sizeof(readBuf)/sizeof(char), fpFile );
		nTotalCount += count;

		if(*ppReadBuf == NULL)
		{
			if((*ppReadBuf = (char*)calloc(count + 1, 1)) == NULL)
			{
				nRet = -1;
				goto err;
			}

			memcpy(*ppReadBuf, readBuf, count);
		}
		else
		{
			char *pTempBuf = NULL;

			if((pTempBuf = (char*)calloc(nTotalCount + count, 1)) == NULL)
			{
				nRet = -1;
				goto err;
			}

			memcpy(pTempBuf, *ppReadBuf, nTotalCount);
			free(*ppReadBuf);
			*ppReadBuf = pTempBuf;

			memcpy(*ppReadBuf + nTotalCount, readBuf, count);
			nTotalCount += count;
		}
	}

err:

	if(fpFile)
		fclose(fpFile);

	return nRet;
}

int WriteTxtFile(char *szFilePath, char *pWriteBuf)
{
	int nRet = 0;
	FILE *fpFile = NULL;

	if((fpFile = fopen(szFilePath, "w+")) == NULL)
	{
		nRet = -1;
		goto err;
	}

	if(fwrite(pWriteBuf, 1, strlen(pWriteBuf), fpFile) != strlen(pWriteBuf))
	{
		nRet = -1;
		goto err;
	}	

err:

	if(fpFile)
		fclose(fpFile);

	return nRet;
}