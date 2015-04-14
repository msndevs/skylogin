#ifndef __COMMON_H__
#define __COMMON_H__

#ifdef WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock.h>
#pragma comment (lib,"ws2_32.lib")
#define int64_t __int64

#else

#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
typedef int SOCKET;
#define closesocket close
typedef int BOOL;
#define TRUE  1
#define FALSE 0

#endif

#ifdef DEBUG
#include <stdio.h>
#define DBGPRINT printf
#else
#define DBGPRINT
#endif

#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

typedef	 unsigned char		uchar;
typedef	 unsigned short		ushort;
typedef	 unsigned int		uint;
typedef	 unsigned long		ulong;

#define	 MAX_IP_LEN			15
#define	 HTTPS_PORT			443

#define	 NODEID_SZ			8
#define	 HANDSHAKE_SZ		0x05
#define  CONCAT_SALT		"\nskyper\n"
#define  KEYSZ				0x200
#define	 SK_SZ				0xC0
#define  MODULUS_SZ			0x80
#define  HTTPS_HSR_MAGIC	"\x16\x03\x01"
#define  HTTPS_HSRR_MAGIC	"\x17\x03\x01"
#define	 LOGIN_OK			4200

#define	 RAW_PARAMS			0x41
#define	 EXT_PARAMS			0x42

#define	 VER_STR			"0/6.18.0.105"

typedef  struct
{
	char		ip[MAX_IP_LEN + 1];
	int			port;
} Host;

typedef struct
{
	uchar	*Memory;
	int 	MsZ;
}	Memory_U;

typedef struct
{
	//uchar		*User;
	uint		Expiry;
	RSA			*RSAKeys;
	//Memory_U	Modulus;
	Memory_U	SignedCredentials;
}	SLoginDatas;

typedef struct
{
	uchar			SessionKey[SK_SZ];
	uchar			NodeID[NODEID_SZ];
	uchar			Language[2];
	uint			PublicIP;
	SLoginDatas		LoginD; 
}	Skype_Inst;

#pragma	pack(1)
typedef struct
{
	unsigned char  MAGIC[3];
	unsigned short ResponseLen;
}	HttpsPacketHeader;

#pragma pack()

extern char				*SkypeModulus1536[];

char *KeySelect(uint KeyIndex);
#endif
