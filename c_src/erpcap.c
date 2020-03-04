// erpcap.c: 定义应用程序的入口点。
//

#include <stdio.h>
#include <string.h>
#include "erpcap.h"
#include "erpcap_comm.h"
#include <stdlib.h>

int write_memory(byte* buf, unsigned int len, struct erpcap_memory *chunk)
{
    unsigned int realsize = chunk->data_len + len;
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
    struct erpcap_msg_base_s *msg;

#ifdef WIN32
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
        return(-1);

    while (read_cmd(&chunk) > 0) {
        msg = (struct erpcap_msg_base_s *)chunk.mem;

        switch(msg->cmd) {
            case erpcap_cmd_list:
                if(list_if(&chunk) < 0) {
                    goto _abort;
                }
                if(write_cmd(&chunk) <= 0) {
                    goto _abort;
                }
                break;
            case erpcap_cmd_listen:
                break;
            case erpcap_cmd_send:
                break;
            case erpcap_cmd_exit:
            default:
                goto _abort;
        }
    }

_abort:
    free(chunk.mem);
    return(-1);
}
