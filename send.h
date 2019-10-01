#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pcap.h>

struct ether_header {
	uint8_t	ether_dhost[6];
	uint8_t	ether_shost[6];
	uint16_t ether_type;
};

struct arp_header {
	uint16_t arp_hrd;
	uint16_t arp_pro;
	uint8_t arp_hln;
	uint8_t arp_pln;
	uint16_t arp_op;
	uint8_t arp_sha[6];
	uint8_t arp_spa[4];
	uint8_t arp_tha[6];
	uint8_t arp_tpa[4];
};

void get_my_ip(uint8_t * my_ip, char * interface);
void get_my_mac(uint8_t * my_mac, char * interface);
void get_sender_mac(uint8_t * my_mac, uint8_t * sender_mac, uint8_t * my_ip, uint8_t * sender_ip, pcap_t *fp);
void send_pkt(uint8_t * d_mac, uint8_t * s_mac, uint8_t * f_mac, uint8_t * d_ip, uint8_t * s_ip, uint16_t arp_operand, pcap_t *fp);
void add_to_num(char * address, uint8_t * ip);
