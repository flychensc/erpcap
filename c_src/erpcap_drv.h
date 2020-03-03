#ifndef _ERPCAP_DRV_H_
#define _ERPCAP_DRV_H_

int list_if(char* buf);
int listen(int if_id);
int recv_packet(char* buf, int len);
int send_packet(char* buf, int len);
#endif
