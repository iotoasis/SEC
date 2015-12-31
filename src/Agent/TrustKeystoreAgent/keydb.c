#include "keydb.h"
#include "../sqlite3/sqlite3.h"

int TK_GetKeyFromDB(char *szKeyDBFile, char *szKeyID, Key *pKey)
{
	int nRet = 0;
	sqlite3* db = NULL;
	char szQuery[100] = "";
	sqlite3_stmt* stmt = NULL;
#ifndef NO_KEY_DB
	sprintf(szQuery, "SELECT * FROM TKS_KEY WHERE key_id = '%s'", szKeyID);
	
	if(sqlite3_open_v2(szKeyDBFile, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_SQLITE3_OPEN_V2;
		goto error;
	}
	if((nRet = sqlite3_exec(db, "BEGIN", 0, 0, 0)) != SQLITE_OK)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_SQLITE3_SQLITE3_EXEC;
		goto error;
	}
	if((nRet = sqlite3_prepare(db, szQuery, -1, &stmt, NULL)) != SQLITE_OK)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_SQLITE3_SQLITE3_PREPARE;
		goto error;
	}
	while (sqlite3_step(stmt) == SQLITE_ROW)
	{			
		if(sqlite3_column_bytes(stmt, 0) != 0)
		{
			strncpy(pKey->key_id, (char*)sqlite3_column_text(stmt, 0), sizeof(pKey->key_id) -1);
		}
		if(sqlite3_column_bytes(stmt, 1) != 0)
		{
			strncpy(pKey->enc_key_value, (char*)sqlite3_column_text(stmt, 1), sizeof(pKey->enc_key_value));
		}
		if(sqlite3_column_bytes(stmt, 2) != 0)
		{
			strncpy(pKey->key_algo, (char*)sqlite3_column_text(stmt, 2), sizeof(pKey->key_algo));
		}
		if(sqlite3_column_bytes(stmt, 3) != 0)
		{
			strncpy(pKey->op_mode, (char*)sqlite3_column_text(stmt, 3), sizeof(pKey->op_mode));
		}
		if(sqlite3_column_bytes(stmt, 4) != 0)
		{
			strncpy(pKey->expose_level, (char*)sqlite3_column_text(stmt, 4), sizeof(pKey->expose_level));
		}
		if(sqlite3_column_bytes(stmt, 5) != 0)
		{
			strncpy(pKey->valid_start, (char*)sqlite3_column_text(stmt, 5), sizeof(pKey->valid_start));
		}
		if(sqlite3_column_bytes(stmt, 6) != 0)
		{
			strncpy(pKey->valid_end, (char*)sqlite3_column_text(stmt, 6), sizeof(pKey->valid_end));
		}
		if(sqlite3_column_bytes(stmt, 7) != 0)
		{
			strncpy(pKey->key_hmac, (char*)sqlite3_column_text(stmt, 7), sizeof(pKey->key_hmac));
		}
	}

	if((nRet = sqlite3_exec(db, "END", 0, 0, 0)) != SQLITE_OK)
	{
		nRet = g_nAgentErrorCode = TK_AGENT_ERROR_FAILED_SQLITE3_SQLITE3_EXEC;
		goto error;
	}

error:

	sqlite3_finalize(stmt);
	sqlite3_close(db);
#endif
return nRet;
}
