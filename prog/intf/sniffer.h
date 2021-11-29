#pragma once
#include<pcap.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<menu.h>
#include "windows.h"

void start_capture(char * devname,WIN * win);
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
void init_sniffer();
ITEM ** packet_menu_entry(int row_len);
char *packet_menu_header(int row_len);
int trackConversations(const struct pcap_pkthdr *header, const u_char *buffer);
void parseConvo(int conv_key);
void setDisable(int x);
int getDisable();
char * get_ethernet_header(int key,int row_len);
char ** get_ipv4_header(int key,int row_len);
char ** get_tcp_packet(int key, int row_len);