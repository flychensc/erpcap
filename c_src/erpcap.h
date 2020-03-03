#ifndef _ERPCAP_H_
#define _ERPCAP_H_

typedef unsigned char byte;

struct erpcap_memory
{
	unsigned int size;	// memory size
	void *mem;

	unsigned int data_len;	// valid data length
};

enum erpcap_cmd_e
{
	erpcap_cmd_exit = 0,
	erpcap_cmd_list = 1,
	erpcap_cmd_listen = 2,
	erpcap_cmd_send = 3,
	erpcap_cmd_recv = 4,

	erpcap_cmd_last
};

struct erpcap_msg_base_s
{
	enum erpcap_cmd_e cmd;
};

struct erpcap_msg_iflist_s
{
	enum erpcap_cmd_e cmd;
	int msg_len;
	char msg[0];
};

struct erpcap_msg_bindif_s
{
	enum erpcap_cmd_e cmd;
	int if_id;
};

struct erpcap_msg_pkt_s
{
	enum erpcap_cmd_e cmd;
	int pkt_len;
	byte buf[0];
};

#endif
