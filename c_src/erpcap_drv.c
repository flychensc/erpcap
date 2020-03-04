#include <pcap.h>
#include <stdio.h>
#ifdef WIN32
#include <tchar.h>
BOOL LoadNpcapDlls()
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
