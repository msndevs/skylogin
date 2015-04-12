#include <stdio.h>
#include <stdlib.h>
#include "skylogin.h"

int main(int argc, char **argv)
{
	SkyLogin *hLogin;
	char *pszUIC;

	if (argc<4)
	{
		printf ("Usage: %s <User> <Pass> <Nonce>\n\n"
			"i.e.: %s oj.one canastas 5d679ff8-5bf4-fdff-ab76-d17c91413d78\n", 
			argv[0], argv[0]);
		return -1;
	}
	if (!(hLogin = SkyLogin_Init()))
	{
		fprintf (stderr, "Error: OOM!\n");
		return -1;
	}
	if (!(SkyLogin_PerformLogin(hLogin, argv[1], argv[2])))
	{
		fprintf (stderr, "Error: Login failed!\n");
		return -1;
	}

	pszUIC = SkyLogin_CreateUICString(hLogin, argv[3]);
	printf ("Your UIC is:\n%s\n", pszUIC);
	free(pszUIC);

	SkyLogin_Exit(hLogin);

	return 0;
}
