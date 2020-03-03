#include "erpcap_comm.h"
#include <io.h>

/* [read|write]_exact are used since they may return
* BEFORE all bytes have been transmitted
*/
static int read_exact(byte* buf, unsigned int len)
{
    unsigned int i, got = 0;

    do {
        if ((i = _read(0, buf + got, len - got)) <= 0)
            return(i);
        got += i;
    } while (got < len);

    return(got);
}

static int write_exact(byte* buf, unsigned int len)
{
    unsigned int i, wrote = 0;

    do {
        if ((i = _write(1, buf + wrote, len - wrote)) <= 0)
            return (i);
        wrote += i;
    } while (wrote < len);

    return (wrote);
}

/* Read the 2 length bytes (MSB first), then the data. */
int read_cmd(struct erpcap_memory *chunk)
{
    byte buf[2];

    if (read_exact(buf, 2) != 2)
        return(-1);
    chunk->size = (buf[0] << 8) | buf[1];
    return read_exact(chunk->mem, chunk->size);
}

/* Pack the 2 bytes length (MSB first) and send it */
int write_cmd(struct erpcap_memory *chunk)
{
    byte li;

    li = (chunk->size >> 8) & 0xff;
    write_exact(&li, 1);

    li = chunk->size & 0xff;
    write_exact(&li, 1);

    return write_exact(chunk->mem, chunk->size);
}
