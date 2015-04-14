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
 * Module:       Main module which contains public functions of library
 *
 */
#ifdef WIN32
#define EXPORT __declspec(dllexport)
#endif
#include "common.h"
#include "login.h"
#include "platform.h"
#include "uic.h"
#include "skylogin.h"

EXPORT SkyLogin *SkyLogin_Init()
{
	Skype_Inst *pInst = calloc(1, sizeof(Skype_Inst));

#ifdef WIN32
	WORD wVersionRequested;
	WSADATA wsaData;

	wVersionRequested = MAKEWORD( 2, 2 );
	WSAStartup( wVersionRequested, &wsaData);
#endif

	if (pInst) InitInstance(pInst);
	return (SkyLogin*)pInst;
}

EXPORT void SkyLogin_Exit(SkyLogin *pPInst)
{
	Skype_Inst *pInst = (Skype_Inst*)pPInst;
	if (pInst->LoginD.RSAKeys) RSA_free(pInst->LoginD.RSAKeys);
	if (pInst->LoginD.SignedCredentials.Memory) free(pInst->LoginD.SignedCredentials.Memory);
	free(pInst);
}

EXPORT int SkyLogin_PerformLogin(SkyLogin *pInst, char *User, char *Pass)
{
	return PerformLogin((Skype_Inst*)pInst, User, Pass);
}

EXPORT char *SkyLogin_CreateUICString(SkyLogin *pInst, const char *pszNonce)
{
	return CreateUICString((Skype_Inst*)pInst, pszNonce, "WS-SecureConversationSESSION KEY TOKEN");
}
