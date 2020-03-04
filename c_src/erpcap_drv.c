#include <stdio.h>
#include "erpcap_drv.h"
#include "erpcap_comm.h"

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

static pcap_t *adhandle = NULL;

int pcap_list(struct erpcap_memory *chunk)
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

/* Callback function invoked by libpcap for every incoming packet */
static void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct erpcap_memory chunk;

	// header->ts.tv_sec

	chunk.size = header->len;
	chunk.data_len = header->len;
	chunk.mem = pkt_data;

	write_cmd(&chunk);	
}

int pcap_listen(unsigned char* name)
{
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
	
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	
	pcap_close(adhandle);
	return 0;
}

int pcap_send(byte* pkt, size_t len)
{
	/* Send down the packet */
	if (pcap_sendpacket(adhandle,	// Adapter
		pkt,				// buffer with the packet
		len					// size
		) != 0)
	{
		fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
		return -1;
	}

	return 0;
}