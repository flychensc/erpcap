#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <stdio.h>

#ifndef WIN32
	#include <sys/socket.h>
	#include <netinet/in.h>
#else
	#include <winsock.h>
	#include <ws2tcpip.h>
#endif

#include "erpcap_drv.h"
#include "erpcap_comm.h"

static pcap_t *adhandle = NULL;

#ifdef WIN32
BOOL WINAPI ConsoleHandler(DWORD dwCtrlType)
{
	closeif();

	return TRUE;
}

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

// Function prototypes
static void ifprint(pcap_if_t *d);
static char *iptos(u_long in);
static char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);

void iflist(void)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i=0;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Scan the list printing every entry */
	for(d=alldevs;d;d=d->next)
	{
		ifprint(d);
	}

	/* Free the device list */
	pcap_freealldevs(alldevs);
}

/* Print all the available information on the given interface */
static void ifprint(pcap_if_t *d)
{
  pcap_addr_t *a;
  char ip6str[128];

  /* Name */
  printf("%s\n",d->name);

  /* Description */
  if (d->description)
    printf("\tDescription: %s\n",d->description);

  /* Loopback Address*/
  printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

  /* IP addresses */
  for(a=d->addresses;a;a=a->next) {
    printf("\tAddress Family: #%d\n",a->addr->sa_family);
  
    switch(a->addr->sa_family)
    {
      case AF_INET:
        printf("\tAddress Family Name: AF_INET\n");
        if (a->addr)
          printf("\tAddress: %s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
        if (a->netmask)
          printf("\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
        if (a->broadaddr)
          printf("\tBroadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
        if (a->dstaddr)
          printf("\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
        break;

	  case AF_INET6:
       printf("\tAddress Family Name: AF_INET6\n");
#ifndef __MINGW32__ /* Cygnus doesn't have IPv6 */
        if (a->addr)
          printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
#endif
		break;

	  default:
        printf("\tAddress Family Name: Unknown\n");
        break;
    }
  }
  printf("\n");
}

/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS	12
static char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

#ifndef __MINGW32__ /* Cygnus doesn't have IPv6 */
static char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;

	#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
	#else
	sockaddrlen = sizeof(struct sockaddr_storage);
	#endif


	if(getnameinfo(sockaddr, 
		sockaddrlen, 
		address, 
		addrlen, 
		NULL, 
		0, 
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}
#endif /* __MINGW32__ */

/* Callback function invoked by libpcap for every incoming packet */
static void packet_handler(u_char *param, const struct pcap_pkthdr *header, u_char *pkt_data)
{
	// header->ts.tv_sec
	write_cmd(pkt_data, header->len);
}

int openif(unsigned char* name)
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

	// printf("\nlistening on %s...\n", d->description);
	
	/* start the capture */
	pcap_dispatch(adhandle, 0, (pcap_handler)packet_handler, NULL);

	return 0;
}

void closeif(void)
{
	if (NULL != adhandle) {
		pcap_close(adhandle);
		adhandle = NULL;
	}
}

int sendpkt(byte* pkt, int len)
{
	if (!adhandle)
	{
		return -1;
	}

	/* Send down the packet */
	if (pcap_sendpacket(adhandle,	// Adapter
		pkt,						// buffer with the packet
		len							// size
		) != 0)
	{
		fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(adhandle));
		return -1;
	}

	return 0;
}
