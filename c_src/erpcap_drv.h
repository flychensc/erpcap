#ifndef _ERPCAP_DRV_H_
#define _ERPCAP_DRV_H_

#include <pcap.h>
#include "erpcap.h"

#ifdef WIN32
#include <tchar.h>
BOOL WINAPI ConsoleHandler(DWORD dwCtrlType);
BOOL LoadNpcapDlls(void);
#endif

int pcap_list(struct erpcap_memory *chunk);
int pcap_listen(unsigned char* name);
int pcap_send(byte* pkt, size_t len);

#endif
