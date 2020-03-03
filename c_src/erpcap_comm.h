#ifndef _ERPCAP_COMM_H_
#define _ERPCAP_COMM_H_

#include "erpcap.h"

/* Read the 2 length bytes (MSB first), then the data. */
int read_cmd(struct erpcap_memory *chunk);

/* Pack the 2 bytes length (MSB first) and send it */
int write_cmd(struct erpcap_memory *chunk);

#endif
