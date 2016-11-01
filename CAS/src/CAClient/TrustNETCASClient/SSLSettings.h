#ifndef SSLSETTINGS_H
#define SSLSETTINGS_H



// Wolf SSL Settings
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>


#ifdef USE_WINDOWS_API 
	#include <winsock2.h>
	#include <process.h>
	#ifdef TEST_IPV6            /* don't require newer SDK for IPV4 */
		#include <ws2tcpip.h>
		#include <wspiapi.h>
	#endif
	#define SOCKET_T SOCKET
	#define SNPRINTF _snprintf
#elif defined(WOLFSSL_MDK_ARM)
	#include <string.h>
#elif defined(WOLFSSL_TIRTOS)
	#include <string.h>
	#include <netdb.h>
	#include <sys/types.h>
	#include <arpa/inet.h>
	#include <sys/socket.h>
	#include <ti/sysbios/knl/Task.h>
	#define SOCKET_T int
#else
	#include <string.h>
	#include <sys/types.h>
	#ifndef WOLFSSL_LEANPSK
		#include <unistd.h>
		#include <netdb.h>
		#include <netinet/in.h>
		#include <netinet/tcp.h>
		#include <arpa/inet.h>
		#include <sys/ioctl.h>
		#include <sys/time.h>
		#include <sys/socket.h>
		#include <pthread.h>
		#include <fcntl.h>
		#include <errno.h>
		#ifdef TEST_IPV6
			#include <netdb.h>
		#endif
	#endif
	#define SOCKET_T int
	#ifndef SO_NOSIGPIPE
		#include <signal.h>  /* ignore SIGPIPE */
	#endif
	#define SNPRINTF snprintf
#endif /* USE_WINDOWS_API */

#ifdef TEST_IPV6
typedef struct sockaddr_in6 SOCKADDR_IN_T;
#define AF_INET_V    AF_INET6
#else
typedef struct sockaddr_in  SOCKADDR_IN_T;
#define AF_INET_V    AF_INET
#endif

#ifdef USE_WINDOWS_API 
#define CloseSocket(s) closesocket(s)
//#define StartTCP() { WSADATA wsd; WSAStartup(0x0002, &wsd); }
#define StartTCP() { WSADATA wsd; WSAStartup(MAKEWORD(2,2), &wsd); }
#define EndTCP() WSACleanup();
#elif defined(WOLFSSL_MDK_ARM)
#define CloseSocket(s) closesocket(s)
#define StartTCP() 
#define EndTCP()
#else
#define CloseSocket(s) close(s)
#define StartTCP() 
#define EndTCP()
#endif

// static INLINE void err_sys(const char* msg)
// {
// 	printf("wolfSSL error: %s\n", msg);
// 	if (msg)
// 		exit(EXIT_FAILURE);
// }

static INLINE int build_addr(SOCKADDR_IN_T* addr, const char* peer,
	word16 port, int udp)
{
	int nRet = 0;
	int useLookup = 0;
	(void)useLookup;
	(void)udp;

	memset(addr, 0, sizeof(SOCKADDR_IN_T));

#ifndef TEST_IPV6
	/* peer could be in human readable form */
	if ( (peer != INADDR_ANY) && isalpha((int)peer[0])) {
#ifdef WOLFSSL_MDK_ARM
		int err;
		struct hostent* entry = gethostbyname(peer, &err);
#else
		struct hostent* entry = gethostbyname(peer);
#endif

		if (entry) {
			memcpy(&addr->sin_addr.s_addr, entry->h_addr_list[0],
				entry->h_length);
			useLookup = 1;
		}
		else
		{
			nRet = -1;
			goto error;
			//err_sys("no entry for host");
		}
	}
#endif


#ifndef TEST_IPV6
#if defined(WOLFSSL_MDK_ARM)
	addr->sin_family = PF_INET;
#else
	addr->sin_family = AF_INET_V;
#endif
	addr->sin_port = htons(port);
	if (peer == INADDR_ANY)
		addr->sin_addr.s_addr = INADDR_ANY;
	else {
		if (!useLookup)
			addr->sin_addr.s_addr = inet_addr(peer);
	}
#else
	addr->sin6_family = AF_INET_V;
	addr->sin6_port = htons(port);
	if (peer == INADDR_ANY)
		addr->sin6_addr = in6addr_any;
	else {
#ifdef HAVE_GETADDRINFO
		struct addrinfo  hints;
		struct addrinfo* answer = NULL;
		int    ret;
		char   strPort[80];

		memset(&hints, 0, sizeof(hints));

		hints.ai_family   = AF_INET_V;
		hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
		hints.ai_protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;

		SNPRINTF(strPort, sizeof(strPort), "%d", port);
		strPort[79] = '\0';

		ret = getaddrinfo(peer, strPort, &hints, &answer);
		if (ret < 0 || answer == NULL)
		{
			nRet = -1;
			goto error;
			//err_sys("getaddrinfo failed");
		}

		memcpy(addr, answer->ai_addr, answer->ai_addrlen);
		freeaddrinfo(answer);
#else
		printf("no ipv6 getaddrinfo, loopback only tests/examples\n");
		addr->sin6_addr = in6addr_loopback;
#endif
	}
#endif

error:

	return nRet;
}


static INLINE int tcp_socket(SOCKET_T* sockfd, int udp)
{
	int nRet = 0;

	if (udp)
		*sockfd = socket(AF_INET_V, SOCK_DGRAM, 0);
	else
		*sockfd = socket(AF_INET_V, SOCK_STREAM, 0);

#ifdef USE_WINDOWS_API
	if (*sockfd == INVALID_SOCKET)
	{
		nRet = -1;
		goto error;
		//err_sys("socket failed\n");
	}
#elif defined(WOLFSSL_TIRTOS)
	if (*sockfd == -1)
	{
		nRet = -1;
		goto error;
		//err_sys("socket failed\n");
	}

#else
	if (*sockfd < 0)
	{
		nRet = -1;
		goto error;
		//err_sys("socket failed\n");
	}
#endif

#ifndef USE_WINDOWS_API 
	#ifdef SO_NOSIGPIPE
		{
			int       on = 1;
			socklen_t len = sizeof(on);
			if((nRet= setsockopt(*sockfd, SOL_SOCKET, SO_NOSIGPIPE, &on, len)) < 0)
				goto error;
		}
	#elif defined(WOLFSSL_MDK_ARM) || defined (WOLFSSL_TIRTOS)
		/* nothing to define */
	#else  /* no S_NOSIGPIPE */
		signal(SIGPIPE, SIG_IGN);
	#endif /* S_NOSIGPIPE */

	#if defined(TCP_NODELAY)
		if (!udp)
		{
			int       on = 1;
			socklen_t len = sizeof(on);
			if((nRet= setsockopt(*sockfd, IPPROTO_TCP, TCP_NODELAY, &on, len)) < 0)
				goto error;
		}
	#endif
#endif  /* USE_WINDOWS_API */

#ifndef USE_WINDOWS_API 
		{
			struct timeval tvTimeout;
			struct linger   ling;

			tvTimeout.tv_sec = 5;  /* 5 Secs Timeout */
			tvTimeout.tv_usec =0;			

			ling.l_onoff = 1;
			ling.l_linger = 0;      /* 0 for abortive disconnect */


			setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, (void*)&tvTimeout, sizeof(tvTimeout));
			setsockopt(*sockfd, SOL_SOCKET, SO_SNDTIMEO, (void*)&tvTimeout, sizeof(tvTimeout));

			setsockopt(*sockfd, SOL_SOCKET, SO_LINGER, (void*)&ling, sizeof(ling));

		}
#else
		{
			DWORD dwTimeout = 5000; /* 5 Secs Timeout */
			struct linger   ling;
			DWORD       on = 1;

			ling.l_onoff = 1;
			ling.l_linger = 0;      /* 0 for abortive disconnect */


			setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO,(const char *)&dwTimeout,sizeof(DWORD));
			setsockopt(*sockfd, SOL_SOCKET, SO_SNDTIMEO,(const char *)&dwTimeout,sizeof(DWORD));

			setsockopt(*sockfd, SOL_SOCKET, SO_LINGER, (const char *)&ling, sizeof(ling));

			if((nRet= setsockopt(*sockfd, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(on))) < 0)
				goto error;

		}
#endif

error:
	return nRet;
}

static INLINE int tcp_connect(SOCKET_T* sockfd, const char* ip, word16 port, int udp)
{
	int nRet = 0;
#ifndef USE_WINDOWS_API 
	int curFlags;
#else
	unsigned long arg;
#endif	
	SOCKADDR_IN_T addr;
	if((nRet = build_addr(&addr, ip, port, udp)) != 0)
		goto error;
	if((nRet = tcp_socket(sockfd, udp)) != 0)
		goto error;

	if (!udp)
	{
		fd_set  rset, wset; 
		struct timeval tval;

#ifndef USE_WINDOWS_API 
		curFlags = fcntl(*sockfd, F_GETFL, 0);
		fcntl(*sockfd, F_SETFL, curFlags|O_NONBLOCK);
#else
		arg = 1;
		ioctlsocket(*sockfd, FIONBIO, &arg);
#endif

		if(connect(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
		{
#ifndef USE_WINDOWS_API 
			if(errno != EINPROGRESS)
#else
			if(WSAGetLastError() != WSAEWOULDBLOCK)
#endif
			{
				nRet = -1;
				goto error;
			}
		}
		else
		{
			// 정상 접속
			goto error;
		}
		FD_ZERO(&rset); 
		FD_SET(*sockfd, &rset); 
		wset = rset; 
 
		tval.tv_sec     = 3;	// connect timeout 3 sec
		tval.tv_usec    = 0; 

		if(select((*sockfd)+1, &rset, &wset, NULL, &tval) == 0) 
		{ 
			// timeout
			nRet = -2;
			goto error; 
		}
		else
		{
			if (FD_ISSET(*sockfd, &rset) || FD_ISSET(*sockfd, &wset))
			{
				int error;
				int len = sizeof(int);

				if (getsockopt(*sockfd, SOL_SOCKET, SO_ERROR, (char*)&error, &len) < 0)
				{
					nRet = -1;
					goto error;
				}
			}
		}
	}

error:

#ifndef USE_WINDOWS_API 	
	fcntl(*sockfd, F_SETFL, curFlags);
#else
	arg = 0;
	ioctlsocket(*sockfd, FIONBIO, &arg);
#endif

	return nRet;
}


// static INLINE void showPeer(WOLFSSL* ssl)
// {
// 
// 	WOLFSSL_CIPHER* cipher;
// #ifdef KEEP_PEER_CERT
// 	WOLFSSL_X509* peer = wolfSSL_get_peer_certificate(ssl);
// 	if (peer)
// 		ShowX509(peer, "peer's cert info:");
// 	else
// 		printf("peer has no cert!\n");
// #endif
// 	printf("SSL version is %s\n", wolfSSL_get_version(ssl));
// 
// 	cipher = wolfSSL_get_current_cipher(ssl);
// 	printf("SSL cipher suite is %s\n", wolfSSL_CIPHER_get_name(cipher));
// 
// #if defined(SESSION_CERTS) && defined(SHOW_CERTS)
// 	{
// 		WOLFSSL_X509_CHAIN* chain = wolfSSL_get_peer_chain(ssl);
// 		int                count = wolfSSL_get_chain_count(chain);
// 		int i;
// 
// 		for (i = 0; i < count; i++) {
// 			int length;
// 			unsigned char buffer[3072];
// 			WOLFSSL_X509* chainX509;
// 
// 			wolfSSL_get_chain_cert_pem(chain,i,buffer, sizeof(buffer), &length);
// 			buffer[length] = 0;
// 			printf("cert %d has length %d data = \n%s\n", i, length, buffer);
// 
// 			chainX509 = wolfSSL_get_chain_X509(chain, i);
// 			if (chainX509)
// 				ShowX509(chainX509, "session cert info:");
// 			else
// 				printf("get_chain_X509 failed\n");
// 			wolfSSL_FreeX509(chainX509);
// 		}
// 	}
// #endif
// 	(void)ssl;
// }


#endif // SSLSETTINGS_H
