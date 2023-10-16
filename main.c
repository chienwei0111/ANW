#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include "arp.h"
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <arpa/inet.h>


/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
#define DEVICE_NAME "enp0s3"
#define ARPOP_REQUEST 1
#define ARPHRD_ETHER 1
#define ARPOP_REPLY 2
/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */
void print_buffer(const unsigned char *bufer,int lingth){
	for (int i =0; i<lingth; i++){
		printf("%02x ", bufer[i]);
		
	}
	printf("\n");
}
int main(int argc,char *argv[])
{
	int sockfd = 0,specific=0;
	struct sockaddr_ll sa;
	struct ifreq req;
	socklen_t addr_len = sizeof(sa);
	unsigned char buffer[1024];
	//struct in_addr myip;
	//Part 1 - Check if the current user is root.
	uid_t uid =geteuid();
	if (uid != 0)
	{
		printf("Error, You must be root use tool!\n");
		return 1;
	}

	if (argc > 1 )
	{
		if (!argv[1])
			print_usage();
		//Part 1 - Show the detail of the option.
		if (strcmp(argv[1], "-help") == 0 )
			print_usage();
		else if  (strcmp(argv[1], "-l") == 0) 
		{	
			if(!argv[2])
			{
				print_usage();
				exit(1);
			}
			//Part 1 - Show all of ARP packets.
			if(strcmp(argv[2], "-a"))
				specific = 1;
			
			//Create a socket.
			if((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
			{
				perror("open recv socket error");
				exit(1);
			}
			while(1)
			{
				int num_bytes = recvfrom(sockfd, buffer,sizeof(buffer),0,(struct sockaddr *)&sa, &addr_len);
				if (num_bytes == -1) 
				{
					perror("recvfrom failed");
					close(sockfd);
					exit(1);
				 }
				//Because the received data is stored in buffer
				 struct arp_packet *arp = (struct arp_packet *)buffer;

				if (ntohs(arp->arp.arp_op)== ARPOP_REQUEST)
				{
					char *target_ip = get_target_protocol_addr(&arp->arp);
					char *sender_ip = get_sender_protocol_addr(&arp->arp);
					if(specific==1)
					{
						if(strcmp(argv[2],target_ip) == 0)
							printf("Get ARP packet - who has %s ? Tell %s\n",target_ip,sender_ip);
					}else
						printf("Get ARP packet - who has %s ? Tell %s\n",target_ip,sender_ip);

				}	
			}
		} else if (strcmp(argv[1], "-q") == 0)
		{
			struct arp_packet fp;
			if (!argv[2])
			{
				print_usage();
				exit(1);
			}
			if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
			{
				perror("open recv socket error");
				exit(1);
			}
			strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ - 1);
			//ioctl to get IP address (SIOCGIFADDR)
			if (ioctl(sockfd,SIOCGIFADDR,&req)<0)
				perror("ioctl failed");
			
			struct sockaddr_in *addr= (struct sockaddr_in *)&req.ifr_addr;
			char *src_ip = inet_ntoa(addr->sin_addr); 
			//ioctl to get MAC address (SIOCGIFHWADDR) 
			if (ioctl(sockfd,SIOCGIFHWADDR,&req)<0)
				perror("ioctl failed");
			struct ether_addr *mac = (struct ether_addr *)&req.ifr_hwaddr.sa_data;
				
			memcpy(fp.eth_hdr.ether_dhost,"\xFF\xFF\xFF\xFF\xFF\xFF",ETH_ALEN);
			memcpy(fp.eth_hdr.ether_shost,mac->ether_addr_octet,ETH_ALEN);
			fp.eth_hdr.ether_type = htons(ETH_P_ARP);
			set_hard_type(&fp.arp,ARPHRD_ETHER);
			set_prot_type(&fp.arp,ETH_P_IP);
			set_hard_size(&fp.arp,ETH_ALEN);
			set_prot_size(&fp.arp,4);
			set_op_code(&fp.arp,ARPOP_REQUEST);
			set_sender_hardware_addr(&fp.arp,(char *)mac->ether_addr_octet);
			set_sender_protocol_addr(&fp.arp,src_ip);
			set_target_protocol_addr(&fp.arp,argv[2]);
			set_target_hardware_addr(&fp.arp,"\xFF\xFF\xFF\xFF\xFF\xFF");
			
			memset(&sa,0,sizeof(sa));
			sa.sll_ifindex = if_nametoindex(DEVICE_NAME);
			sa.sll_protocol = htons(ETH_P_ARP);
			
			sendto(sockfd,&fp,sizeof(fp), 0, (struct sockaddr *)&sa, sizeof(sa));
			
			int num_bytes = recvfrom(sockfd, buffer,sizeof(buffer),0,(struct sockaddr *)&sa, &addr_len);
			if (num_bytes == -1) 
			{
				perror("error!");
				close(sockfd);
				exit(1);
			}

			struct arp_packet *arp = (struct arp_packet *)buffer;

			if (ntohs(arp->arp.arp_op)== ARPOP_REPLY)
			{
				//printf("recive arp reqeuest\n");
				//print_buffer(buffer,num_bytes);
				char *sender_mac = get_sender_hardware_addr(&arp->arp);
				char *sender_ip = get_sender_protocol_addr(&arp->arp);
					
				printf("MAC address of %s is %s\n",sender_ip,sender_mac);
				 	
				free(sender_mac);
				free(sender_ip);
			 }
			
			
		}
		else{
			
			if((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
			{
				perror("open recv socket error");
				exit(1);
			}
			while(1)
			{	
				int num_bytes = recvfrom(sockfd, buffer,sizeof(buffer),0,(struct sockaddr *)&sa, &addr_len);
				if (num_bytes == -1) 
				{
					perror("error!");
					close(sockfd);
					exit(1);
				}

				struct arp_packet *arp = (struct arp_packet *)buffer;
				if (ntohs(arp->arp.arp_op)== ARPOP_REQUEST)
				{
					struct arp_packet fp;	
					char *target_ip=get_target_protocol_addr(&arp->arp);
					if(strcmp(argv[2],target_ip) == 0)
					{
						char *sender_ip = get_sender_protocol_addr(&arp->arp);
						char *sender_mac=get_sender_hardware_addr(&arp->arp);
						uint8_t *macAddress = convert_string_to_uint8(argv[1]);	
						printf("Get ARP packet - Who has %s ?	tell %s.\n",target_ip,sender_ip);
					
						strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ - 1);					
						if(ioctl(sockfd, SIOCGIFHWADDR, &req)<0)
							perror("ioctl failed");
						
						memcpy(fp.eth_hdr.ether_dhost,arp->arp.arp_sha,ETH_ALEN);
						memcpy(fp.eth_hdr.ether_shost,(char *)macAddress,ETH_ALEN);
						fp.eth_hdr.ether_type = htons(ETH_P_ARP);
						set_hard_type(&fp.arp,ARPHRD_ETHER);
						set_prot_type(&fp.arp,ETH_P_IP);
						set_hard_size(&fp.arp,ETH_ALEN);
						set_prot_size(&fp.arp,4);
						set_op_code(&fp.arp,ARPOP_REPLY);
						set_sender_hardware_addr(&fp.arp,(char *)macAddress);
						set_sender_protocol_addr(&fp.arp,target_ip);
						set_target_protocol_addr(&fp.arp,sender_ip);
						set_target_hardware_addr(&fp.arp,(char *)arp->arp.arp_sha);
						//print_buffer((unsigned char *)macAddress,sizeof(macAddress));	
						printf ("Sent ARP Replay : %s is %s\n",target_ip,argv[1]);
						
						memset(&sa,0,sizeof(sa));
						sa.sll_ifindex = if_nametoindex(DEVICE_NAME);
						sa.sll_protocol = htons(ETH_P_ARP);
						//while(1)
						//{
							int sent_bytes=sendto(sockfd,&fp,sizeof(fp), 0, (struct sockaddr *)&sa, sizeof(sa));
							if (sent_bytes == -1)
							{
								perror("sendto failed\n");
								free(sender_mac);
								free(sender_ip);
								close(sockfd);
								exit(1);
							}else
							{
								printf("Send successfully.\n");
							}
						//}
						free(sender_mac);
						free(sender_ip);
						free(target_ip);
						break;
					}else continue;

				}	 	
					
			}
		}
	}


	close(sockfd);
	return 0;
	
}

