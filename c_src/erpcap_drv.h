#ifndef _ERPCAP_DRV_H_
#define _ERPCAP_DRV_H_

#include <pcap.h>
#include "erpcap.h"

#ifdef WIN32
#include <tchar.h>
BOOL LoadNpcapDlls(void);
#endif

int list_if(struct erpcap_memory *chunk);
int listen_if(unsigned char* name, struct erpcap_memory *chunk);
int recv_packet(char* buf, int len);
int send_packet(char* buf, int len);
#endif
