// erpcap.c: 定义应用程序的入口点。
//

#include <stdio.h>
#include <string.h>
#include "erpcap.h"
#include "erpcap_comm.h"
#include <stdlib.h>

int main(int argc, char** argv)
{
    struct erpcap_memory chunk;
    struct erpcap_msg_base_s *msg;

    chunk.size = 2048;
    chunk.mem = malloc(chunk.size);
    if (!chunk.mem)
        return(-1);

    while (read_cmd(&chunk) > 0) {
        msg = (struct erpcap_msg_base_s *)chunk.mem;

        switch(msg->cmd) {
            case erpcap_cmd_list:
                break;
            case erpcap_cmd_listen:
                break;
            case erpcap_cmd_send:
                break;
            case erpcap_cmd_exit:
            default:
                free(chunk.mem);
                return(-1);
        }
    }
}
