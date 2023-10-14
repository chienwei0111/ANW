#include "arp.h"

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

//You can fill the following functions or add other functions if needed. If not, you needn't write anything in them.  
void set_hard_type(struct ether_arp *packet, unsigned short int type)
{
	packet->arp_hrd = htons(type);
	
}
void set_prot_type(struct ether_arp *packet, unsigned short int type)
{
	packet->arp_pro = htons(type);
	
}
void set_hard_size(struct ether_arp *packet, unsigned char size)
{
	packet->arp_hln = size ;
	
}
void set_prot_size(struct ether_arp *packet, unsigned char size)
{
	packet->arp_pln = size ;
	
}
void set_op_code(struct ether_arp *packet, short int code)
{
	packet->arp_op = htons(code);
}

void set_sender_hardware_addr(struct ether_arp *packet, char *address)
{
	memcpy(packet->arp_sha,address,ETH_ALEN);
	
}
void set_sender_protocol_addr(struct ether_arp *packet, char *address)
{
	inet_pton(AF_INET,address,packet->arp_spa);
}
void set_target_hardware_addr(struct ether_arp *packet, char *address)
{
	memcpy(packet->arp_tha,address,ETH_ALEN);
}
void set_target_protocol_addr(struct ether_arp *packet, char *address)
{
	inet_pton(AF_INET,address,packet->arp_tpa);
}

char* get_target_protocol_addr(struct ether_arp *packet)
{
	char *buffer = malloc(20);
	sprintf(buffer,"%d.%d.%d.%d",
	packet->arp_tpa[0],packet->arp_tpa[1],packet->arp_tpa[2],packet->arp_tpa[3]);// if you use malloc, remember to free it.
	
	return buffer;
}
char* get_sender_protocol_addr(struct ether_arp *packet)
{
	char *buffer = malloc(20);
	sprintf(buffer,"%d.%d.%d.%d",
	packet->arp_spa[0],packet->arp_spa[1],packet->arp_spa[2],packet->arp_spa[3]);// if you use malloc, remember to free it.
	
	return buffer;
}
char* get_sender_hardware_addr(struct ether_arp *packet)
{
	char *buffer = malloc(60);
	sprintf(buffer,"%02X:%02X:%02X:%02X:%02X:%02X",
	packet->arp_sha[0],packet->arp_sha[1],packet->arp_sha[2],packet->arp_sha[3],packet->arp_sha[4],packet->arp_sha[5]);
	
	return buffer;
	// if you use malloc, remember to free it.
}
char* get_target_hardware_addr(struct ether_arp *packet)
{
	char *buffer = malloc(60);
	sprintf(buffer,"%02X:%02X:%02X:%02X:%02X:%02X",
	packet->arp_tha[0],packet->arp_tha[1],packet->arp_tha[2],packet->arp_tha[3],packet->arp_tha[4],packet->arp_tha[5]);
	
	return buffer;
	// if you use malloc, remember to free it.
}
void print_usage()
{
   printf("[ ARP sniffer and spoof program ]\n");
   printf("Format :\n");
   printf("1) ./arp -l -a)\n");
   printf("2) ./arp -l <filter_ip_address>)\n");
   printf("3) ./arp -l <query_ip_address>)\n");
   printf("4) ./arp  <fake_mac_address> <target_ip_address)\n");
}