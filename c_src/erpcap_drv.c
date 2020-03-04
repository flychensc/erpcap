#include <stdio.h>
#include "erpcap_drv.h"

#ifdef WIN32
BOOL LoadNpcapDlls(void)
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

int list_if(struct erpcap_memory *chunk)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return (-1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		write_memory(d->name, strlen(d->name), chunk);
		if (d->description)
			write_memory(d->description, strlen(d->description), chunk);
		else
			write_memory("No description available", strlen("No description available"), chunk);
	}
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	return 0;
}

int listen_if(unsigned char* name, struct erpcap_memory *chunk)
{
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if ((adhandle= pcap_open_live(name,		// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", name);
		return -1;
	}
	write_memory("ok", strlen("ok"), chunk);
	return 0;
}