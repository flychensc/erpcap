#ifndef _ERPCAP_H_
#define _ERPCAP_H_

typedef unsigned char byte;

struct erpcap_memory
{
	size_t size;	// memory size
	void *mem;

	size_t data_len;	// valid data length
};

size_t write_memory(byte* buf, size_t len, struct erpcap_memory *chunk);

/*
Message send from erlang

list interface:
REQ_MSG

bind interface:
REQ_MSG NAME

send packet:
PKT
*/

#define ERPCAP_REQ_MSG_LIST		1	// list interface
#define ERPCAP_REQ_MSG_LISTEN 	2	// bind interface

/*
Message send to erlang

interface list:
COUNT [(NAME_LEN, NAME, DESC_LEN, DESC),]

receive packet:
PKT
*/

#endif
