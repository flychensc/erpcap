#ifndef _ERPCAP_DRV_H_
#define _ERPCAP_DRV_H_

#include <pcap.h>
#include "erpcap.h"

#ifdef WIN32
#include <tchar.h>
BOOL WINAPI ConsoleHandler(DWORD dwCtrlType);
BOOL LoadNpcapDlls(void);
#endif

void iflist(void);
int openif(unsigned char* name);
void closeif(void);
int sendpkt(byte* pkt, int len);

#endif
