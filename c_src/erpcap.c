// erpcap.c: 定义应用程序的入口点。
//

#include <stdio.h>
#include <string.h>
#include "erpcap.h"
#include "erpcap_comm.h"
#include "erpcap_drv.h"
#include <stdlib.h>

size_t write_memory(byte* buf, size_t len, struct erpcap_memory *chunk)
{
    size_t realsize = chunk->data_len + len;
    byte *blank;

    if (realsize > chunk->size) {
        chunk->size = realsize;
        chunk->mem = realloc(chunk->mem, chunk->size);
        if (!chunk->mem)
            return(-1);
    }

    blank = (byte *)chunk->mem + chunk->data_len;
    memcpy(blank, buf, len);
    chunk->data_len += len;

    return len;
}

int main(int argc, char** argv)
{
    struct erpcap_memory chunk;
    byte *msg;
    long cmd;

#ifdef WIN32
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		return(-1);
	}
#endif

    chunk.size = 2048;
    chunk.mem = malloc(chunk.size);
    if (!chunk.mem)
    {
        fprintf(stderr, "Couldn't alloc memory\n");
        return(-1);
    }

    while (read_cmd(&chunk) > 0) {
        msg = (byte *)chunk.mem;
        cmd = msg[0];

        switch(cmd) {
            case ERPCAP_REQ_MSG_LIST:
            {
                if (pcap_list(&chunk) < 0) {
                    fprintf(stderr, "Couldn't list interface\n");
                    goto _abort;
                }
                if(write_cmd(&chunk) <= 0) {
                    fprintf(stderr, "Couldn't write stdout\n");
                    goto _abort;
                }
                break;
            }
            case ERPCAP_REQ_MSG_LISTEN:
            {
                if (pcap_listen(msg+1) < 0) {
                    fprintf(stderr, "Couldn't open interface\n");
                    goto _abort;
                }
                if(write_cmd(&chunk) <= 0) {
                    fprintf(stderr, "Couldn't write stdout\n");
                    goto _abort;
                }
                goto _loop;
            }

            default:
                fprintf(stderr, "Unknown command\n");
                goto _abort;
        }
    }

_loop:
    while (read_cmd(&chunk) > 0) {
        pcap_send(chunk.mem, chunk.data_len);
    }

_abort:
    free(chunk.mem);
    return(-1);
}
