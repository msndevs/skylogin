/*  
 * Skype Login
 * 
 * Based on:
 *   FakeSkype : Skype reverse engineering proof-of-concept client
 *               Ouanilo MEDEGAN (c) 2006   http://www.oklabs.net
 *   pyskype   : Skype login Python script by uunicorn
 *
 * Written by:   leecher@dose.0wnz.at (c) 2015 
 *
 * Module:       Skype server login
 *
 */
#include "common.h"
#include "objects.h"
#include "random.h"
#include "platform.h"
#include "crc.h"
#ifdef _DEBUG
#include <time.h>
#endif

#ifdef USE_RC4
#include "rc4comm.c"
#else
#define RC4Comm_Init(conn) 0
#define RC4Comm_Send(conn,buf,len) send(conn->LSSock,buf,len,0)
#define RC4Comm_Recv(conn,buf,len) recv(conn->LSSock,buf,len,0)
#endif

static Host LoginServers[] = {
	{"91.190.216.17", 33033},
	{"91.190.218.40", 33033},
};

static BOOL SendHandShake2LS(LSConnection *pConn, Host *CurLS)
{
	uchar				HandShakePkt[HANDSHAKE_SZ] = {0};
	HttpsPacketHeader	*HSHeader, Response;
	struct sockaddr_in	Sender={0};

	HSHeader = (HttpsPacketHeader *)HandShakePkt;
	memcpy(HSHeader->MAGIC, HTTPS_HSR_MAGIC, sizeof(HSHeader->MAGIC));
	HSHeader->ResponseLen = 0;
	DBGPRINT("Sending Handshake to Login Server %s..\n", CurLS->ip);
	Sender.sin_family = AF_INET;
	Sender.sin_port = htons((short)CurLS->port);
	Sender.sin_addr.s_addr = inet_addr(CurLS->ip);
	if (connect(pConn->LSSock, (struct sockaddr *)&Sender, sizeof(Sender)) < 0)
	{
		DBGPRINT("Connection refused..\n");
		return FALSE;
	}
	if (RC4Comm_Init(pConn) < 0 ||
		RC4Comm_Send(pConn, (const char *)HandShakePkt, HANDSHAKE_SZ)<=0 ||
		RC4Comm_Recv(pConn, (char*)&Response, sizeof(Response))<=0 ||
		memcmp(Response.MAGIC, HTTPS_HSRR_MAGIC, sizeof(Response.MAGIC)))
		return FALSE;
	return TRUE;
}

/* If Pass is NULL, User is assumed to be OAuth string and OAuth logon is performed */
static int SendAuthentificationBlobLS(Skype_Inst *pInst, LSConnection *pConn, const char *User, const char *Pass)
{
	uchar				AuthBlob[0xFFFF] = {0};
	uchar				SHAResult[32] = {0};
	uchar				Modulus[MODULUS_SZ * 2] = {0};
	uchar				ivec[AES_BLOCK_SIZE] = {0};
	uchar				ecount_buf[AES_BLOCK_SIZE] = {0};
	uint				MiscDatas[0x05] = {0};
	uchar				SessionKey[SK_SZ];
	uchar				*Browser;
	uchar				*MarkObjL;
	uint				Idx, Size, Crc, BSize, ret = 0;
	HttpsPacketHeader	*HSHeader;
	uchar				HSHeaderBuf[sizeof(HttpsPacketHeader)], RecvBuf[0x1000];
	AES_KEY				AesKey;
	MD5_CTX				Context;
	RSA					*SkypeRSA;
	SResponse			Response={0};
	

	if (!pInst->LoginD.RSAKeys)
	{
		BIGNUM				*KeyExp;

		DBGPRINT("Generating RSA Keys Pair (Size = %d Bits)..\n", KEYSZ);
		pInst->LoginD.RSAKeys = RSA_new();
		KeyExp = BN_new();
		BN_set_word(KeyExp, RSA_F4);
		Idx = RSA_generate_key_ex(pInst->LoginD.RSAKeys, KEYSZ * 2, KeyExp, NULL);
		BN_free(KeyExp);
		if (Idx == -1)
		{
			DBGPRINT("Error generating Keys..\n\n");
			RSA_free(pInst->LoginD.RSAKeys);
			pInst->LoginD.RSAKeys = NULL;
			return (0);
		}
	}

	Idx = BN_bn2bin(pInst->LoginD.RSAKeys->n, Modulus);
	Idx = BN_bn2bin(pInst->LoginD.RSAKeys->d, Modulus + Idx);

	Browser = AuthBlob;

	HSHeader = (HttpsPacketHeader *)Browser;
	memcpy(HSHeader->MAGIC, HTTPS_HSR_MAGIC, sizeof(HSHeader->MAGIC));
	HSHeader->ResponseLen = htons(0xCD);
	Browser += sizeof(HttpsPacketHeader);

	*Browser++ = RAW_PARAMS;
	*Browser++ = 0x03;

	WriteNbrObject(&Browser, OBJ_ID_2000, 0x2000);

	SpecialSHA(pInst->SessionKey, SK_SZ, SHAResult, 32);
	AES_set_encrypt_key(SHAResult, 256, &AesKey);

	SkypeRSA = RSA_new();
	BN_hex2bn(&(SkypeRSA->n), SkypeModulus1536[1]);
	BN_hex2bn(&(SkypeRSA->e), "010001");
	Idx = RSA_public_encrypt(SK_SZ, pInst->SessionKey, SessionKey, SkypeRSA, RSA_NO_PADDING);
	RSA_free(SkypeRSA);
	if (Idx < 0)
	{
		DBGPRINT("RSA_public_encrypt failed..\n\n");
		return (0);
	}

	WriteBlobObject(&Browser, OBJ_ID_SK, SessionKey, SK_SZ);

	WriteNbrObject(&Browser, OBJ_ID_ZBOOL1, 0x01);

	HSHeader = (HttpsPacketHeader *)Browser;
	memcpy(HSHeader->MAGIC, HTTPS_HSRR_MAGIC, sizeof(HSHeader->MAGIC));
	HSHeader->ResponseLen = 0x00;
	Browser += sizeof(HttpsPacketHeader);

	MarkObjL = Browser;
	if (Pass)
	{
		*Browser++ = RAW_PARAMS;
		*Browser++ = 0x04;

		WriteNbrObject(&Browser, OBJ_ID_REQCODE, 0x1399);

		WriteNbrObject(&Browser, OBJ_ID_ZBOOL2, 0x01);

		WriteStringObject(&Browser, OBJ_ID_USERNAME, User, strlen(User));

		MD5_Init(&Context);
		MD5_Update(&Context, User, (ulong)strlen(User));
		MD5_Update(&Context, CONCAT_SALT, (ulong)strlen(CONCAT_SALT));
		MD5_Update(&Context, Pass, (ulong)strlen(Pass));
		MD5_Final(pInst->LoginD.LoginHash, &Context);

		WriteBlobObject(&Browser, OBJ_ID_USERPASS, pInst->LoginD.LoginHash, MD5_DIGEST_LENGTH);

		*Browser++ = RAW_PARAMS;
		*Browser++ = 0x06;

		WriteBlobObject(&Browser, OBJ_ID_MODULUS, Modulus, MODULUS_SZ);

		WriteTableObject(&Browser, OBJ_ID_PLATFORM, PlatFormSpecific());

		WriteStringObject(&Browser, OBJ_ID_LANG, pInst->Language, sizeof(pInst->Language));

		FillMiscDatas(pInst, MiscDatas);
		WriteIntListObject(&Browser, OBJ_ID_MISCD, MiscDatas, 0x05);

		WriteStringObject(&Browser, OBJ_ID_VERSION, VER_STR, strlen(VER_STR));

		WriteNbrObject(&Browser, OBJ_ID_PUBADDR, pInst->PublicIP);
	}
	else
	{
		// OAuth logon
		*Browser++ = RAW_PARAMS;
		*Browser++ = 0x02;

		WriteNbrObject(&Browser, OBJ_ID_REQCODE, 0x13a3);

		WriteNbrObject(&Browser, OBJ_ID_ZBOOL2, 0x3d);

		*Browser++ = RAW_PARAMS;
		*Browser++ = 0x08;

		WriteBlobObject(&Browser, OBJ_ID_MODULUS, Modulus, MODULUS_SZ);

		WriteTableObject(&Browser, OBJ_ID_PLATFORM, PlatFormSpecific());

		FillMiscDatas(pInst, MiscDatas);
		WriteIntListObject(&Browser, OBJ_ID_MISCD, MiscDatas, 0x05);

		WriteStringObject(&Browser, OBJ_ID_LANG, pInst->Language, sizeof(pInst->Language));

		WriteTableObject(&Browser, OBJ_ID_PARTNERID, 999);

		WriteStringObject(&Browser, OBJ_ID_OAUTH, User, strlen(User));

		WriteStringObject(&Browser, OBJ_ID_VERSION, VER_STR, strlen(VER_STR));

		WriteNbrObject(&Browser, OBJ_ID_PUBADDR, pInst->PublicIP);
	}

	Size = (uint)(Browser - MarkObjL);
	HSHeader->ResponseLen = htons((u_short)(Size + 0x02));

	Idx = 0;
	memset(ivec, 0, AES_BLOCK_SIZE);
	memset(ecount_buf, 0, AES_BLOCK_SIZE);
	AES_ctr128_encrypt(MarkObjL, MarkObjL, Size, &AesKey, ivec, ecount_buf, &Idx);

	Crc = crc32(MarkObjL, Size, -1);
	*Browser++ = *((uchar *)(&Crc) + 0);
	*Browser++ = *((uchar *)(&Crc) + 1);

	Size = (uint)(Browser - AuthBlob);

	if (RC4Comm_Send(pConn, (const char *)AuthBlob, Size)<=0)
	{
		DBGPRINT("Sending to LS failed :'(..\n");
		return (-1);
	}

	while (!ret && RC4Comm_Recv(pConn, (char *)&HSHeaderBuf, sizeof(HSHeaderBuf))>0)
	{
		HSHeader = (HttpsPacketHeader *)HSHeaderBuf;
		if (strncmp((const char *)HSHeader->MAGIC, HTTPS_HSRR_MAGIC, strlen(HTTPS_HSRR_MAGIC)) ||
			RC4Comm_Recv(pConn, (char *)RecvBuf, (BSize=htons(HSHeader->ResponseLen)))<=0)
		{
			DBGPRINT("Bad Response..\n");
			return (-2);
		}
		DBGPRINT("Auth Response Got..\n\n");

		Idx = 0;
		memset(ivec, 0, AES_BLOCK_SIZE);
		memset(ecount_buf, 0, AES_BLOCK_SIZE);
		BSize-=2;
		ivec[3] = 0x01;
		ivec[7] = 0x01;
		AES_ctr128_encrypt(RecvBuf, RecvBuf, BSize, &AesKey, ivec, ecount_buf, &Idx);

		Browser = RecvBuf;
		while (Browser<RecvBuf+BSize)
			ManageObjects(&Browser, BSize, &Response);
		for (Idx = 0; Idx < Response.NbObj; Idx++)
		{
			switch (Response.Objs[Idx].Id)
			{
			case OBJ_ID_LOGINANSWER:
				switch (Response.Objs[Idx].Value.Nbr)
				{
				case LOGIN_OK:
					DBGPRINT("Login Successful..\n");
					ret = 1;
					break;
				default :
					DBGPRINT("Login Failed.. Bad Credentials..\n");
					FreeResponse(&Response);
					return 0;
				}
				break;
			case OBJ_ID_CIPHERDLOGD:
				if (pInst->LoginD.SignedCredentials.Memory) free(pInst->LoginD.SignedCredentials.Memory);
				if (!(pInst->LoginD.SignedCredentials.Memory = malloc(Response.Objs[Idx].Value.Memory.MsZ)))
				{
					FreeResponse(&Response);
					return -2;
				}
				memcpy (pInst->LoginD.SignedCredentials.Memory, Response.Objs[Idx].Value.Memory.Memory, 
					(pInst->LoginD.SignedCredentials.MsZ = Response.Objs[Idx].Value.Memory.MsZ));				
				break;
			}
		}
		FreeResponse(&Response);
	}

	return ret;
}


int PerformLogin(Skype_Inst *pInst, const char *User, const char *Pass)
{
	uint			ReUse = 1;
	int				i;
	LSConnection	conn={0};
	int				iRet = 0;

	for (i=0; !iRet && i<sizeof(LoginServers)/sizeof(LoginServers[0]); i++)
	{
		conn.LSSock = socket(AF_INET, SOCK_STREAM, 0);
		setsockopt(conn.LSSock, SOL_SOCKET, SO_REUSEADDR, (const char *)&ReUse, sizeof(ReUse));

		if (SendHandShake2LS(&conn, &LoginServers[i]))
		{
			DBGPRINT("Login Server %s OK ! Let's authenticate..\n", LoginServers[i].ip);
			iRet = SendAuthentificationBlobLS(pInst, &conn, User, Pass);
		}
		closesocket(conn.LSSock);
	}

	if (!iRet) DBGPRINT("Login Failed..\n");
	return iRet;
}


void InitInstance(Skype_Inst *pInst)
{
	memset(pInst, 0, sizeof(Skype_Inst));
	GenSessionKey(pInst->SessionKey, sizeof(pInst->SessionKey));
	InitNodeId(pInst);
	memcpy(pInst->Language, "en", 2);
	pInst->PublicIP = 0x7F000001;	// 127.0.0.1, we could use hostscan to get real IP, but not necessary for just login
}
