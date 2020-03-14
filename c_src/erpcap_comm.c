#include "erpcap_comm.h"

#ifdef WIN32
#include <windows.h>
/* [read|write]_exact are used since they may return
* BEFORE all bytes have been transmitted
*/
static int read_exact(byte* buf, int len)
{
    int i, got = 0;

    do {
        if (!ReadFile(STD_INPUT_HANDLE, buf + got, len - got, &i, NULL))
            return(-1);
        got += i;
    } while (got < len);

    return(len);
}

static int write_exact(byte* buf, int len)
{
    int i, wrote = 0;

    do {
        if (!WriteFile(STD_OUTPUT_HANDLE, buf + wrote, len - wrote, &i, NULL))
            return (-1);
        wrote += i;
    } while (wrote < len);

    return (len);
}
#endif
/* Read the 2 length bytes (MSB first), then the data. */
int read_cmd(byte *buf)
{
    int len;

    if (read_exact(buf, 2) != 2)
        return(-1);
    len = (buf[0] << 8) | buf[1];
    return read_exact(buf, len);
}

/* Pack the 2 bytes length (MSB first) and send it */
int write_cmd(byte *buf, int len)
{
    byte li;

    li = (len >> 8) & 0xff;
    write_exact(&li, 1);
    
    li = len & 0xff;
    write_exact(&li, 1);

    return write_exact(buf, len);
}
