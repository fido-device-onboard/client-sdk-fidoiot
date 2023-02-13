// win_client.c : This file contains the 'main' function. Program execution begins and ends there.
//

#include <stdio.h>
#include <stdbool.h>
#include <WinSock2.h>
#include "safe_lib.h"


//extern int app_main(bool is_resale);
extern int app_main(bool is_resale, bool useSelfSignedCerts);

int main(int argc, char *argv[])
{
	WSADATA wsaData;
	bool do_resale = false;
	bool useSelfSignedCerts = false;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		return 1;
	}

	if (argc > 1 && *argv[1] == '1') {
		do_resale = true;
	}

#if defined SELF_SIGNED_CERTS_SUPPORTED
	int strcmp_ss = 1;
	int res = -1;
	
	res = (int)strcmp_s((char *)argv[1], 4, "-ss", &strcmp_ss);

	if (argc > 1 && (!res && !strcmp_ss)) {
		useSelfSignedCerts = true;
	}
#endif

	printf("Windows\n");
	app_main(do_resale, useSelfSignedCerts);
}

