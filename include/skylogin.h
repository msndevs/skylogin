typedef void* SkyLogin;

/* Size of the buffer you should supply as pszOutUIC on SkyLogin_CreateUICString */
#define UICSTR_SIZE	1024

#ifndef EXPORT
#define EXPORT
#endif

/* Initialize SkyLogin Instance */
EXPORT SkyLogin SkyLogin_Init();

/* Uninitialize Skylogin Instance */
EXPORT void SkyLogin_Exit(SkyLogin pInst);

/* Perform login with Username and Password 
 * Returns:
 * 1 on success, 0 on failure, -1 on socket error, -2 on bad response */
EXPORT int SkyLogin_PerformLogin(SkyLogin pInst, char *pszUser, char *pszPass);

/* Creates UIC string from nonce pszNonce and places it in pszOutUIC
 * pszOutUIC buffer should be at least UICSTR_SIZE in size.
 *
 * Returns:
 * Size of UIC string in Bytes on success, 0 on failure
 */
EXPORT int SkyLogin_CreateUICString(SkyLogin pInst, const char *pszNonce, char *pszOutUIC);

