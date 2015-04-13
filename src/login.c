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

static Host LoginServers[] = {
	/*
	{"213.166.51.4", 33033},
	{"193.88.6.13", 33033},
	{"194.165.188.79", 33033},
	{"195.46.253.219", 33033},*/
	{"91.190.216.17", 33033},
	{"91.190.218.40", 33033},
	{0, 0}
};

static BOOL SendHandShake2LS(SOCKET LSSock, Host *CurLS)
{
	uchar				HandShakePkt[HANDSHAKE_SZ] = {0};
	HttpsPacketHeader	*HSHeader, Response;
	struct sockaddr_in	Sender={0};

	HSHeader = (HttpsPacketHeader *)HandShakePkt;
	memcpy(HSHeader->MAGIC, HTTPS_HSR_MAGIC, sizeof(HSHeader->MAGIC));
	HSHeader->ResponseLen = 0;
	DBGPRINT("Sending Handshake to Login Server %s..\n", CurLS->ip);
	Sender.sin_family = AF_INET;
	Sender.sin_port = htons(HTTPS_PORT);
	Sender.sin_addr.s_addr = inet_addr(CurLS->ip);
	if (connect(LSSock, (struct sockaddr *)&Sender, sizeof(Sender)) < 0)
	{
		DBGPRINT("Connection refused..\n");
		return FALSE;
	}
	if (send(LSSock, (const char *)HandShakePkt, HANDSHAKE_SZ, 0)<=0 ||
		recv(LSSock, (char *)&Response, sizeof(Response), 0)<=0 ||
		memcmp(Response.MAGIC, HTTPS_HSRR_MAGIC, sizeof(Response.MAGIC)))
		return FALSE;
	return TRUE;
}

static int SendAuthentificationBlobLS(Skype_Inst *pInst, SOCKET LSSock, char *User, char *Pass)
{
	int64_t				PlatForm;
	uchar				AuthBlob[0xFFFF] = {0};
	uchar				MD5Result[MD5_DIGEST_LENGTH] = {0};
	uchar				SHAResult[32] = {0};
	uchar				Modulus[MODULUS_SZ * 2] = {0};
	uchar				ivec[AES_BLOCK_SIZE] = {0};
	uchar				ecount_buf[AES_BLOCK_SIZE] = {0};
	uint				MiscDatas[0x05] = {0};
	uchar				*Browser;
	uchar				*Mark;
	uchar				*MarkObjL;
	uint				Idx, Size, Crc, BSize;
	HttpsPacketHeader	*HSHeader;
	uchar				HSHeaderBuf[sizeof(HttpsPacketHeader)], RecvBuf[0x1000];
	AES_KEY				AesKey;
	MD5_CTX				Context;
	RSA					*Keys;
	RSA					*SkypeRSA;
	ObjectDesc			Obj2000, ObjSessionKey, ObjZBool1, ObjRequestCode, ObjZBool2, ObjUserName, ObjSharedSecret, ObjModulus, ObjPlatForm, ObjLang, ObjMiscDatas, ObjVer, ObjPubAddr;
	SResponse			Response={0};

	DBGPRINT("Generating RSA Keys Pair (Size = %d Bits)..\n", KEYSZ);
	Keys = RSA_generate_key(KEYSZ * 2, RSA_F4, NULL, NULL);
	if (Keys == NULL)
	{
		DBGPRINT("Error generating Keys..\n\n");
		return (0);
	}

	Idx = BN_bn2bin(Keys->n, Modulus);
	Idx = BN_bn2bin(Keys->d, Modulus + Idx);

	Browser = AuthBlob;

	HSHeader = (HttpsPacketHeader *)Browser;
	memcpy(HSHeader->MAGIC, HTTPS_HSR_MAGIC, sizeof(HSHeader->MAGIC));
	HSHeader->ResponseLen = htons(0xCD);
	Browser += sizeof(HttpsPacketHeader);

	*Browser++ = RAW_PARAMS;
	*Browser++ = 0x03;

	Obj2000.Family = OBJ_FAMILY_NBR;
	Obj2000.Id = OBJ_ID_2000;
	Obj2000.Value.Nbr = 0x2000;
	WriteObject(&Browser, Obj2000);

	SpecialSHA(pInst->SessionKey, SK_SZ, SHAResult, 32);
	AES_set_encrypt_key(SHAResult, 256, &AesKey);

	SkypeRSA = RSA_new();
	BN_hex2bn(&(SkypeRSA->n), SkypeModulus1536[1]);
	BN_hex2bn(&(SkypeRSA->e), "10001");
	RSA_public_encrypt(SK_SZ, pInst->SessionKey, pInst->SessionKey, SkypeRSA, RSA_NO_PADDING);
	RSA_free(SkypeRSA);

	ObjSessionKey.Family = OBJ_FAMILY_BLOB;
	ObjSessionKey.Id = OBJ_ID_SK;
	ObjSessionKey.Value.Memory.Memory = (uchar *)&pInst->SessionKey;
	ObjSessionKey.Value.Memory.MsZ = SK_SZ;
	WriteObject(&Browser, ObjSessionKey);

	ObjZBool1.Family = OBJ_FAMILY_NBR;
	ObjZBool1.Id = OBJ_ID_ZBOOL1;
	ObjZBool1.Value.Nbr = 0x01;
	WriteObject(&Browser, ObjZBool1);

	Mark = Browser;
	HSHeader = (HttpsPacketHeader *)Browser;
	memcpy(HSHeader->MAGIC, HTTPS_HSRR_MAGIC, sizeof(HSHeader->MAGIC));
	HSHeader->ResponseLen = 0x00;
	Browser += sizeof(HttpsPacketHeader);

	MarkObjL = Browser;
	*Browser++ = RAW_PARAMS;
	*Browser++ = 0x04;

	ObjRequestCode.Family = OBJ_FAMILY_NBR;
	ObjRequestCode.Id = OBJ_ID_REQCODE;
	ObjRequestCode.Value.Nbr = 0x1399;
	WriteObject(&Browser, ObjRequestCode);

	ObjZBool2.Family = OBJ_FAMILY_NBR;
	ObjZBool2.Id = OBJ_ID_ZBOOL2;
	ObjZBool2.Value.Nbr = 0x01;
	WriteObject(&Browser, ObjZBool2);

	ObjUserName.Family = OBJ_FAMILY_STRING;
	ObjUserName.Id = OBJ_ID_USERNAME;
	ObjUserName.Value.Memory.Memory = (uchar *)User;
	ObjUserName.Value.Memory.MsZ = (uchar)strlen(User);
	WriteObject(&Browser, ObjUserName);

	MD5_Init(&Context);
	MD5_Update(&Context, User, (ulong)strlen(User));
	MD5_Update(&Context, CONCAT_SALT, (ulong)strlen(CONCAT_SALT));
	MD5_Update(&Context, Pass, (ulong)strlen(Pass));
	MD5_Final(MD5Result, &Context);

	ObjSharedSecret.Family = OBJ_FAMILY_BLOB;
	ObjSharedSecret.Id = OBJ_ID_USERPASS;
	ObjSharedSecret.Value.Memory.Memory = (uchar *)MD5Result;
	ObjSharedSecret.Value.Memory.MsZ = MD5_DIGEST_LENGTH;
	WriteObject(&Browser, ObjSharedSecret);

	*Browser++ = RAW_PARAMS;
	*Browser++ = 0x06;

	ObjModulus.Family = OBJ_FAMILY_BLOB;
	ObjModulus.Id = OBJ_ID_MODULUS;
	ObjModulus.Value.Memory.Memory = (uchar *)Modulus;
	ObjModulus.Value.Memory.MsZ = MODULUS_SZ;
	WriteObject(&Browser, ObjModulus);

	PlatForm = PlatFormSpecific();

	ObjPlatForm.Family = OBJ_FAMILY_TABLE;
	ObjPlatForm.Id = OBJ_ID_PLATFORM;
	memcpy(ObjPlatForm.Value.Table, (uchar *)&PlatForm, sizeof(ObjPlatForm.Value.Table));
	WriteObject(&Browser, ObjPlatForm);

	ObjLang.Family = OBJ_FAMILY_STRING;
	ObjLang.Id = OBJ_ID_LANG;
	ObjLang.Value.Memory.Memory = pInst->Language;
	ObjLang.Value.Memory.MsZ = sizeof(pInst->Language);
	WriteObject(&Browser, ObjLang);

	FillMiscDatas(pInst, MiscDatas);
	ObjMiscDatas.Family = OBJ_FAMILY_INTLIST;
	ObjMiscDatas.Id = OBJ_ID_MISCD;
	ObjMiscDatas.Value.Memory.Memory = (uchar *)MiscDatas;
	ObjMiscDatas.Value.Memory.MsZ = 0x05;
	WriteObject(&Browser, ObjMiscDatas);

	ObjVer.Family = OBJ_FAMILY_STRING;
	ObjVer.Id = OBJ_ID_VERSION;
	ObjVer.Value.Memory.Memory = (uchar *)VER_STR;
	ObjVer.Value.Memory.MsZ = (uchar)strlen(VER_STR);
	WriteObject(&Browser, ObjVer);

	ObjPubAddr.Family = OBJ_FAMILY_NBR;
	ObjPubAddr.Id = OBJ_ID_PUBADDR;
	ObjPubAddr.Value.Nbr = pInst->PublicIP;
	WriteObject(&Browser, ObjPubAddr);

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

	if (send(LSSock, (const char *)AuthBlob, Size, 0)<=0)
	{
		DBGPRINT("Sending to LS failed :'(..\n");
		return (-1);
	}

	while (recv(LSSock, (char *)&HSHeaderBuf, sizeof(HSHeaderBuf), 0)>0)
	{
		HSHeader = (HttpsPacketHeader *)HSHeaderBuf;
		if (strncmp((const char *)HSHeader->MAGIC, HTTPS_HSRR_MAGIC, strlen(HTTPS_HSRR_MAGIC)) ||
			recv(LSSock, (char *)RecvBuf, (BSize=htons(HSHeader->ResponseLen)), 0)<=0)
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
		ManageObjects(&Browser, BSize, &Response);
		for (Idx = 0; Idx < Response.NbObj; Idx++)
		{
			uint LdIdx = 0;

			if (Response.Objs[Idx].Id == OBJ_ID_LOGINANSWER)
			{
				switch (Response.Objs[Idx].Value.Nbr)
				{
				case LOGIN_OK:
					DBGPRINT("Login Successful..\n");
					pInst->LoginD.RSAKeys = Keys;
					FreeResponse(&Response);
					return 1;
				default :
					DBGPRINT("Login Failed.. Bad Credentials..\n");
					FreeResponse(&Response);
					return 0;
				}
				break;
			}
		}
		FreeResponse(&Response);
	}


	return 0;
}


int PerformLogin(Skype_Inst *pInst, char *User, char *Pass)
{
	uint			ReUse = 1;
	int				i;
	SOCKET			LSSock;
	int				iRet = 0;

	for (i=0; !iRet && i<sizeof(LoginServers)/sizeof(LoginServers[0]); i++)
	{
		LSSock = socket(AF_INET, SOCK_STREAM, 0);
		setsockopt(LSSock, SOL_SOCKET, SO_REUSEADDR, (const char *)&ReUse, sizeof(ReUse));

		if (SendHandShake2LS(LSSock, &LoginServers[i]))
		{
			DBGPRINT("Login Server %s OK ! Let's authenticate..\n", LoginServers[i].ip);
			iRet = SendAuthentificationBlobLS(pInst, LSSock, User, Pass);
		}
		closesocket(LSSock);
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
