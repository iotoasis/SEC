#ifndef CASCLIENTCONFIG_H
#define CASCLIENTCONFIG_H


#define CLIENT_CONF_FILE_NAME "TrustNetCaClient.conf"
#define SSL_SERVER_CA_CERT_NAME "trustnetcas-rootca.crt"

#define REQPAGE_REG_DEVICE_GET_DN	"/regDeviceGetDn.cas"
#define REQPAGE_ISSUE_CERT_SIMPLE	"/issueCertSimple.cas"
#define REQPAGE_AUTH_BY_CERT		"/authByCert.cas"

#define TYPE_USER
#define TYPE_DEVICE		"D"

#define SHA_256_LEN			32
#define SHA_256_B64_LEN		44
#define MAX_PATH			260
#define IP_LEN				40
#define PORT_LEN			5
#define CLIENT_ID_LEN		50
#define CLIENT_HINT_LEN		SHA_256_B64_LEN


typedef struct CONFIG {
	char casIP[IP_LEN + 1];
	char casPort[PORT_LEN + 1];
	char clientID[CLIENT_ID_LEN + 1];
	char clientHint[CLIENT_HINT_LEN + 1];
	char clientHomeDir[MAX_PATH];
} Config;
typedef struct CLIENT_CTX {	
	Config*				pConfig; // 설정파일 내용	
	void*				sslCtx;
} Client_CTX;

#endif