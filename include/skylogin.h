typedef void SkyLogin;
#ifndef EXPORT
#define EXPORT
#endif

/* Initialize SkyLogin Instance */
EXPORT SkyLogin *SkyLogin_Init();

/* Uninitialize Skylogin Instance */
EXPORT void SkyLogin_Exit(SkyLogin *pInst);

/* Perform login with Username and Password 
 * Returns:
 * 1 on success, 0 on failure, -1 on socket error, -2 on bad response */
EXPORT int SkyLogin_PerformLogin(SkyLogin *pInst, char *pszUser, char *pszPass);

/* Creates UIC string from nonce pszNonce
 * Returns:
 * Pointer to a string containing UIC, you have to free() it!
 */
EXPORT char *SkyLogin_CreateUICString(SkyLogin *pInst, const char *pszNonce);

