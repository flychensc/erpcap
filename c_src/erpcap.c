// erpcap.c: 定义应用程序的入口点。
//

#include <stdio.h>
#include <string.h>
#include "erpcap.h"
#include "erpcap_comm.h"
#include "erpcap_drv.h"
#include <stdlib.h>

static byte _erpcap_send_pkt_buf[2048] = {0};

static void printhelp(void) {
    printf("\n-l                -- List all interfaces");
    printf("\n-b INTERFACE_NAME -- Bind a interface");
    printf("\n");
}

int main(int argc, char** argv)
{
    int pkt_len;

#ifdef WIN32
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		return(-1);
	}
#endif

    if (argc == 3) {
        if (!strcmp(argv[1], "-b")) {
			if(openif(argv[2]) == 0) {
                goto _main_loop;
            }
		}
    } else if (argc == 2) {
		if (!strcmp(argv[1], "-l")) {
			iflist();
            return(0);
		}
	}

    printhelp();
    return(-1);

_main_loop:
    while ( (pkt_len = read_cmd(_erpcap_send_pkt_buf)) > 0) {
        // send
        sendpkt(_erpcap_send_pkt_buf, pkt_len);
    }

    return(0);
}
