#include "sniffer.h"
#include "constants.h"
#include <stdlib.h>
#include "list.h"
#include <string.h>
#include <menu.h>
#include "utility.h"
#include <pthread.h>
#include "windows.h"
#include <time.h>
#include "convo.h"

pcap_t *handle;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0, i, j;
struct sockaddr_in source, dest;
NODE_PTR head;
NODEC_PTR convo_head;
time_t time_init;
WIN *cap_window;
ITEM **items = NULL;
int convo = 0;
int count = 0;
int disable = 0;
int piggybacking = 0;
int not_piggybacking = 0;
int gmode = 0;
int time_set = 0;
int retransmissions = 0;

void init_sniffer()
{
	head = init_list();
	convo_head = init_listc();
}

void setDisable(int x)
{
	disable = x;
}

int getDisable()
{
	return disable;
}

void save_pcap()
{
	pcap_dumper_t *pd = pcap_dump_open(handle, "dump.pcap");
	if (pd == NULL)
	{
		return;
	}
	NODE_PTR tmp = head;
	if (tmp->next != NULL)
	{
		tmp = tmp->next;
	}
	while (tmp != NULL)
	{
		pcap_dump((u_char *)pd, tmp->header, tmp->buffer);
		tmp = tmp->next;
	}

	pcap_dump_close(pd);
}

void *start_loop(void *dummy)
{
	pcap_loop(handle, 0, process_packet, NULL);
}
void start_capture(char *devname, WIN *win, int mode)
{
	time_t rawtime;
	struct tm *timeinfo;

	if (mode == 0)
		time(&rawtime);
	else
		rawtime = 0;

	timeinfo = localtime(&rawtime);
	time_init = mktime(timeinfo);
	cap_window = win;
	char errbuf[MAX_BUFFER_SIZE];
	if (mode == 0)
	{
		handle = pcap_open_live(devname, 65536, 1, 1000, errbuf);
		if (handle == NULL)
		{
			endwin();
			fprintf(stderr, "Couldn't open device %s : %s\n", devname, errbuf);
			exit(1);
		}
		pthread_t thread_id;
		pthread_create(&thread_id, NULL, start_loop, NULL);
	}
	else
	{
		gmode = 1;
		handle = pcap_open_offline_with_tstamp_precision(devname, 1, errbuf);
		if (handle == NULL)
		{
			endwin();
			fprintf(stderr, "Couldn't open file %s : %s\n", devname, errbuf);
			exit(1);
		}
		pcap_loop(handle, 0, process_packet, NULL);
		updateCapWin(win);
	}
}

void process_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	char *source_ip = (char *)calloc(20, sizeof(char));
	char *destination = (char *)calloc(20, sizeof(char));
	char *protocol = (char *)calloc(10, sizeof(char));
	char *info = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));

	struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

	if (gmode != 0 && time_set == 0)
	{
		time_set = 1;
		time_t rawtime;
		struct tm *timeinfo;
		rawtime = header->ts.tv_sec;
		timeinfo = localtime(&rawtime);
		time_init = mktime(timeinfo);
	}

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	strcpy(source_ip, inet_ntoa(source.sin_addr));
	strcpy(destination, inet_ntoa(dest.sin_addr));
	int key;

	int flag = 1;
	switch (iph->protocol)
	{
	case 6: //TCP Protocol
		++tcp;
		strcpy(protocol, "tcp");
		key = trackConversations(header, buffer);
		break;

	default:
		flag = 0;
		++others;
		break;
	}

	++total;

	if (flag == 1)
	{
		struct pcap_pkthdr *header_tmp = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
		header_tmp->caplen = header->caplen;
		header_tmp->len = header->len;
		struct timeval ts;
		ts = header->ts;
		header_tmp->ts = ts;
		u_char *buf_tmp = (u_char *)malloc(header->caplen);
		memcpy(buf_tmp, buffer, header->caplen);

		insert(&head, tcp, (const struct pcap_pkthdr *)header_tmp, (const u_char *)buf_tmp, source_ip, destination, protocol, info, key);
		parseConvo(key);
		if (disable == 0)
		{
			if (gmode == 0)
				updateCapWin(cap_window);
		}
	}
}

ITEM **packet_menu_entry(int row_len)
{
	//printf("count=%d\n",count);
	if (items == NULL)
	{
		items = (ITEM **)calloc(MAX_PACKETS, sizeof(ITEM *));
	}
	if (row_len < MIN_ENTRY_SIZE)
	{
		row_len = MIN_ENTRY_SIZE;
	}
	int col_no = getPercentageInt(5, row_len);
	int col_time = getPercentageInt(5, row_len);
	int col_source = getPercentageInt(15, row_len);
	int col_dest = getPercentageInt(15, row_len);
	int col_protocol = getPercentageInt(10, row_len);
	int col_length = getPercentageInt(10, row_len);
	int col_info = getPercentageInt(40, row_len);

	char entry_format[MAX_BUFFER_SIZE];
	char desc_format[MAX_BUFFER_SIZE];
	int j = 0;
	NODE_PTR ptr;
	for (ptr = head->next; ptr != NULL && ptr->next != NULL; ptr = ptr->next)
	{
		if (j == (count))
			break;
		j++;
	}
	sprintf(entry_format, "%%-%d.%ds", col_no, col_no);
	sprintf(desc_format, "%%-%d.%ds %%-%d.%ds %%-%d.%ds %%-%d.%ds %%-%d.%ds %%-%d.%ds", col_time, col_time, col_source, col_source, col_dest, col_dest, col_protocol, col_protocol, col_length, col_length, col_info, col_info);
	for (; ptr != NULL && ptr->next != NULL; ptr = ptr->next)
	{
		char *entry = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));
		char *desc = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));
		char *tmp = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));
		sprintf(tmp, "%d", ptr->key);
		sprintf(entry, entry_format, tmp);
		char *tmp2 = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));
		//sprintf(tmp, "%d",ptr->convo);
		sprintf(tmp, "%d", ptr->header->ts.tv_sec - time_init);
		sprintf(tmp2, "%d", ptr->header->len);
		sprintf(desc, desc_format, tmp, ptr->source, ptr->destination, ptr->protocol, tmp2, ptr->info);
		items[count] = new_item(entry, desc);
		count++;
	}
	items[count] = (ITEM *)NULL;
	return items;
}

char *packet_menu_header(int row_len)
{
	int col_no = getPercentageInt(5, row_len);
	int col_time = getPercentageInt(5, row_len);
	int col_source = getPercentageInt(15, row_len);
	int col_dest = getPercentageInt(15, row_len);
	int col_protocol = getPercentageInt(10, row_len);
	int col_length = getPercentageInt(10, row_len);
	int col_info = getPercentageInt(40, row_len);

	char desc_format[MAX_BUFFER_SIZE];

	sprintf(desc_format, "   %%-%d.%ds %%-%d.%ds %%-%d.%ds %%-%d.%ds %%-%d.%ds %%-%d.%ds %%-%d.%ds", col_no, col_no, col_time, col_time, col_source, col_source, col_dest, col_dest, col_protocol, col_protocol, col_length, col_length, col_info, col_info);

	char *desc = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));
	sprintf(desc, desc_format, "S.No", "Time", "Source", "Destination", "Protocol", "Length", "Info");

	return desc;
}

int trackConversations(const struct pcap_pkthdr *header, const u_char *buffer)
{
	struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	unsigned short iphdrlen = iph->ihl * 4;

	struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	char *source_ip = (char *)calloc(20, sizeof(char));
	char *destination = (char *)calloc(20, sizeof(char));
	strcpy(source_ip, inet_ntoa(source.sin_addr));
	strcpy(destination, inet_ntoa(dest.sin_addr));

	uint16_t sport = ntohs(tcph->source);
	uint16_t dport = ntohs(tcph->dest);

	int key = findKeyc(&convo_head, source_ip, destination, sport, dport);

	if (key == -1)
	{
		insertc(&convo_head, convo, source_ip, destination, sport, dport);
		key = convo;
		convo++;
	}

	return key;
}

void parseConvo(int conv_key)
{
	NODE_PTR tmp = find_convo(&head, conv_key);

	if (tmp->next == NULL)
	{
		return;
	}
	else
	{
		tmp = tmp->next;
	}

	unsigned int seq1 = 0;
	unsigned int seq2 = 0;
	unsigned int ack2 = 0;
	unsigned int ack1 = 0;
	unsigned int next_ack1 = 0;
	unsigned int next_ack2 = 0;

	int c1 = 0;
	int c2 = 0;

	int fin = 0;
	int finack = 0;
	int fin2 = 0;
	int finack2 = 0;
	unsigned int finseq1 = 0;
	unsigned int finseq2 = 0;
	while (tmp != NULL)
	{
		if (tmp->buffer == NULL)
		{
			tmp = tmp->next;
			continue;
		}
		struct iphdr *iph = (struct iphdr *)(tmp->buffer + sizeof(struct ethhdr));
		unsigned short iphdrlen = iph->ihl * 4;

		struct tcphdr *tcph = (struct tcphdr *)(tmp->buffer + iphdrlen + sizeof(struct ethhdr));

		int flag1 = 0;
		int flag2 = 0;
		if (strcmp(tmp->info, "") == 0)
		{
			flag1 = 0;
			flag2 = 0;
			updateInfo(&head, tmp->key, "|");
			if ((tcph->urg ^ 1) == 0)
			{
				flag1 = 1;
				updateInfo(&head, tmp->key, "URG|");
			}
			if ((tcph->ack ^ 1) == 0)
			{
				flag2 = 1;
				updateInfo(&head, tmp->key, "ACK|");
			}
			if ((tcph->psh ^ 1) == 0)
			{
				flag1 = 1;
				updateInfo(&head, tmp->key, "PSH|");
			}
			if ((tcph->rst ^ 1) == 0)
			{
				flag1 = 1;
				updateInfo(&head, tmp->key, "RST|");
			}
			if ((tcph->syn ^ 1) == 0)
			{
				flag1 = 1;
				updateInfo(&head, tmp->key, "SYN|");
			}
			if ((tcph->fin ^ 1) == 0)
			{
				flag1 = 1;
				updateInfo(&head, tmp->key, "FIN|");
			}
		}
		int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;
		int data_size = (tmp->header->len - header_size) / 8;

		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->saddr;

		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iph->daddr;

		char *src = (char *)calloc(20, sizeof(char));
		char *dst = (char *)calloc(20, sizeof(char));
		strcpy(src, inet_ntoa(source.sin_addr));
		strcpy(dst, inet_ntoa(dest.sin_addr));
		unsigned int sport = (unsigned int)ntohs(tcph->source);
		unsigned int dport = (unsigned int)ntohs(tcph->dest);

		int fl = flow(&convo_head, src, dst, sport, dport, conv_key);

		NODEC_PTR tmpc = getNodec(&convo_head, conv_key);

		if (c1 == 0 && fl == 1)
		{
			seq1 = ntohl(tcph->th_seq);
			next_ack1 = seq1 + data_size;
			if ((tcph->syn ^ 1) == 0 || (tcph->fin ^ 1) == 0)
			{
				next_ack1 = next_ack1 + 1;
			}
			ack1 = ntohl(tcph->th_ack);
			c1 = 1;
			if ((tcph->fin ^ 1) == 0)
			{
				fin++;
				finseq1=next_ack1;
			}
			if ((tcph->ack ^ 1) == 0)
			{
				if (fin2 > finack2)
				{
					if(ack1==finseq2)
						finack2++;
				}
			}
		}
		else if (c2 == 0 && fl == 0)
		{
			seq2 = ntohl(tcph->th_seq);
			ack2 = ntohl(tcph->th_ack);
			if (flag2 == 1 && next_ack1 != ack2)
			{
				//updateInfo(&head, tmp->key, "RT|");
			}
			next_ack2 = seq2 + data_size;
			if ((tcph->syn ^ 1) == 0 || (tcph->fin ^ 1) == 0)
				next_ack2 += 1;

			c2 = 1;

			if ((tcph->fin ^ 1) == 0)
			{
				fin++;
				finseq2=next_ack2;
			}
			if ((tcph->ack ^ 1) == 0)
			{
				if (fin > finack)
				{
					if(ack2==finseq1)
						finack++;
				}
			}
		}
		else if (fl == 1)
		{
			seq1 = ntohl(tcph->th_seq);
			ack1 = ntohl(tcph->th_ack);

			if (flag2 == 1 && next_ack2 != ack1)
			{
				//updateInfo(&head, tmp->key, "RT|");
			}
			if (data_size > 0 || ((tcph->syn ^ 1) == 0 || (tcph->fin ^ 1) == 0))
			{
				if ((seq1 < next_ack1) && (tcph->rst ^ 1) != 0)
				{
					updateInfo(&head, tmp->key, "RT|");
					if(finishedInfo(&head,tmp->key)==0)
					{
						retransmissions++;
					}
				}
			}
			next_ack1 = seq1 + data_size;
			if ((tcph->syn ^ 1) == 0 || (tcph->fin ^ 1) == 0)
				next_ack1 += 1;

			if ((tcph->fin ^ 1) == 0)
			{
				fin++;
				finseq1=next_ack1;
			}
			if ((tcph->ack ^ 1) == 0)
			{
				if (fin2 > finack2)
				{
					if(ack1==finseq2)
						finack2++;
				}
			}
		}
		else if (fl == 0)
		{
			seq2 = ntohl(tcph->th_seq);
			ack2 = ntohl(tcph->th_ack);
			if (flag2 == 1 && next_ack1 != ack2)
			{
				//updateInfo(&head, tmp->key, "RT|");
			}
			if (data_size > 0 || ((tcph->syn ^ 1) == 0 || (tcph->fin ^ 1) == 0))
			{
				if ((seq2 < next_ack2) && (tcph->rst ^ 1) != 0)
				{
					updateInfo(&head, tmp->key, "RT|");
				}
			}
			next_ack2 = seq2 + data_size;
			if ((tcph->syn ^ 1) == 0 || (tcph->fin ^ 1) == 0)
				next_ack2 += 1;

			if ((tcph->fin ^ 1) == 0)
			{
				fin++;
				finseq2=next_ack2;
			}
			if ((tcph->ack ^ 1) == 0)
			{
				if (fin > finack)
				{
					if(ack2==finseq1)
						finack++;
				}
			}
		}

		if (flag1 == 1 && flag2 == 1)
		{
			piggybacking++;
			updateInfo(&head, tmp->key, "*|");
		}
		else
		{
			not_piggybacking++;
		}

		updateInfo(&head, tmp->key, "~");
		tmp = tmp->next;
		if ((fin >= 1) && (finack >= 1) && (fin2 >=1 ) && (finack2 >= 1))
		{
			setFinishc(&convo_head, tmp->convo);
		}
	}
}

char *get_ethernet_header(int key, int row_len)
{
	NODE_PTR tmp = getNode(&head, key);

	if (tmp == NULL)
	{
		return NULL;
	}

	struct ethhdr *eth = (struct ethhdr *)(tmp->buffer);

	char dest_mac[MAX_BUFFER_SIZE];
	char source_mac[MAX_BUFFER_SIZE];
	sprintf(dest_mac, "MAC destination %.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	sprintf(source_mac, "MAC source %.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);

	char type[MAX_BUFFER_SIZE];
	sprintf(type, "Proto %hu", (unsigned short)eth->h_proto);

	int col_dest = getPercentageInt(40, row_len);
	int col_source = getPercentageInt(40, row_len);
	int col_type = getPercentageInt(10, row_len);

	char *eth_entry = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));
	char entry_format[MAX_BUFFER_SIZE];
	sprintf(entry_format, "%%-%d.%ds | %%-%d.%ds | %%-%d.%ds", col_dest, col_dest, col_source, col_source, col_type, col_type);
	sprintf(eth_entry, entry_format, print_centre(dest_mac, col_dest), print_centre(source_mac, col_source), print_centre(type, col_type));

	return eth_entry;
}

char **get_ipv4_header(int key, int row_len)
{
	unsigned short iphdrlen;
	NODE_PTR tmpn = getNode(&head, key);
	if (tmpn == NULL)
	{
		return NULL;
	}
	struct iphdr *iph = (struct iphdr *)(tmpn->buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	int col_v = getPercentageInt(10, row_len - 10);
	int col_ihl = getPercentageInt(10, row_len - 10);
	int col_tos = getPercentageInt(30, row_len - 10);
	int col_tl = getPercentageInt(50, row_len - 10);

	int col_id = getPercentageInt(50, row_len - 2);
	int col_flags = getPercentageInt(20, row_len - 2);
	int col_foff = getPercentageInt(30, row_len - 2);

	int col_ttl = getPercentageInt(25, row_len - 6);
	int col_proto = getPercentageInt(25, row_len - 6);
	int col_cs = getPercentageInt(50, row_len - 6);

	int col_s = getPercentageInt(100, row_len);

	int col_d = getPercentageInt(100, row_len);

	char entry1_format[MAX_BUFFER_SIZE];
	char entry2_format[MAX_BUFFER_SIZE];
	char entry3_format[MAX_BUFFER_SIZE];
	char entry4_format[MAX_BUFFER_SIZE];
	char entry5_format[MAX_BUFFER_SIZE];

	sprintf(entry1_format, "%%-%d.%ds | %%-%d.%ds | %%-%d.%ds | %%-%d.%ds", col_v, col_v, col_ihl, col_ihl, col_tos, col_tos, col_tl, col_tl);
	sprintf(entry2_format, "%%-%d.%ds | %%-%d.%ds | %%-%d.%ds", col_id, col_id, col_flags, col_flags, col_foff, col_foff);
	sprintf(entry3_format, "%%-%d.%ds | %%-%d.%ds | %%-%d.%ds", col_ttl, col_ttl, col_proto, col_proto, col_cs, col_cs);
	sprintf(entry4_format, "%%-%d.%ds", col_s, col_s);
	sprintf(entry5_format, "%%-%d.%ds", col_d, col_d);

	char *entry1 = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));
	char *entry2 = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));
	char *entry3 = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));
	char *entry4 = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));
	char *entry5 = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));

	char tmp[MAX_BUFFER_SIZE];
	char tmp2[MAX_BUFFER_SIZE];
	char tmp3[MAX_BUFFER_SIZE];
	char tmp4[MAX_BUFFER_SIZE];
	sprintf(tmp, "version %lu", (unsigned int)(iph->version));
	sprintf(tmp2, "ihl %lu", (unsigned int)(iph->ihl) * 4);
	sprintf(tmp3, "type of service %lu", (unsigned int)(iph->tos));
	sprintf(tmp4, "total len %hu", ntohs(iph->tot_len));
	sprintf(entry1, entry1_format, print_centre(tmp, col_v), print_centre(tmp2, col_ihl), print_centre(tmp3, col_tos), print_centre(tmp4, col_tl));

	memset(&tmp, 0, sizeof(tmp));
	memset(&tmp2, 0, sizeof(tmp2));
	memset(&tmp3, 0, sizeof(tmp3));

	sprintf(tmp, "id %hu", ntohs(iph->id));
	sprintf(tmp2, "RF %hu| DF %hu| MF %hu", (uint8_t)((ntohs(iph->frag_off) & IP_RF) != 0), (uint8_t)((ntohs(iph->frag_off) & IP_DF) != 0), (uint8_t)((ntohs(iph->frag_off) & IP_MF) != 0));
	sprintf(tmp3, "Frag offset %hu", (uint16_t)(ntohs(iph->frag_off) & IP_OFFMASK));

	sprintf(entry2, entry2_format, print_centre(tmp, col_id), print_centre(tmp2, col_flags), print_centre(tmp3, col_foff));

	memset(&tmp, 0, sizeof(tmp));
	memset(&tmp2, 0, sizeof(tmp2));
	memset(&tmp3, 0, sizeof(tmp3));

	sprintf(tmp, "Time to live %lu", (unsigned int)iph->ttl);
	sprintf(tmp2, "Protocol %lu", (unsigned int)iph->protocol);
	sprintf(tmp3, "Checksum %hu", (uint16_t)ntohs(iph->check));

	sprintf(entry3, entry3_format, print_centre(tmp, col_ttl), print_centre(tmp2, col_proto), print_centre(tmp3, col_cs));

	char s[MAX_BUFFER_SIZE];
	strcpy(s, "Source ip ");
	sprintf(entry4, entry4_format, print_centre(strcat(s, inet_ntoa(source.sin_addr)), col_s));
	char d[MAX_BUFFER_SIZE];
	strcpy(d, "Destination ip ");
	sprintf(entry5, entry5_format, print_centre(strcat(d, inet_ntoa(dest.sin_addr)), col_d));

	char **entries = (char **)calloc(5, sizeof(char *));
	entries[0] = entry1;
	entries[1] = entry2;
	entries[2] = entry3;
	entries[3] = entry4;
	entries[4] = entry5;

	return entries;
}

char **get_tcp_packet(int key, int row_len)
{
	unsigned short iphdrlen;
	NODE_PTR tmp = getNode(&head, key);
	struct iphdr *iph = (struct iphdr *)(tmp->buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct tcphdr *tcph = (struct tcphdr *)(tmp->buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;

	int col_s = getPercentageInt(47, row_len);
	int col_d = getPercentageInt(47, row_len);

	int col_seq = getPercentageInt(95, row_len);

	int col_acks = getPercentageInt(95, row_len);

	int col_hdl = getPercentageInt(10, row_len);
	int col_rb = getPercentageInt(10, row_len);
	int col_urg = getPercentageInt(5, row_len);
	int col_ack = getPercentageInt(5, row_len);
	int col_psh = getPercentageInt(5, row_len);
	int col_rst = getPercentageInt(5, row_len);
	int col_syn = getPercentageInt(5, row_len);
	int col_fin = getPercentageInt(5, row_len);
	int col_win = getPercentageInt(45, row_len);

	int col_cs = getPercentageInt(47, row_len);
	int col_up = getPercentageInt(47, row_len);

	char entry1_format[MAX_BUFFER_SIZE];
	char entry2_format[MAX_BUFFER_SIZE];
	char entry3_format[MAX_BUFFER_SIZE];
	char entry4_format[MAX_BUFFER_SIZE];
	char entry5_format[MAX_BUFFER_SIZE];

	sprintf(entry1_format, "%%-%d.%ds | %%-%d.%ds", col_s, col_s, col_d, col_d);
	sprintf(entry2_format, "%%-%d.%ds", col_seq, col_seq);
	sprintf(entry3_format, "%%-%d.%ds", col_acks, col_acks);
	sprintf(entry4_format, "%%-%d.%ds | %%-%d.%ds | %%-%d.%ds | %%-%d.%ds | %%-%d.%ds | %%-%d.%ds | %%-%d.%ds | %%-%d.%ds | %%-%d.%ds", col_hdl, col_hdl, col_rb, col_rb, col_urg, col_urg, col_ack, col_ack, col_psh, col_psh, col_rst, col_rst, col_syn, col_syn, col_fin, col_fin, col_win, col_win);
	sprintf(entry5_format, "%%-%d.%ds | %%-%d.%ds", col_cs, col_cs, col_up, col_up);

	char *entry1 = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));
	char *entry2 = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));
	char *entry3 = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));
	char *entry4 = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));
	char *entry5 = (char *)calloc(MAX_BUFFER_SIZE, sizeof(char));

	char tmp1[MAX_BUFFER_SIZE];
	char tmp2[MAX_BUFFER_SIZE];
	sprintf(tmp1, "source port %lu", (unsigned int)ntohs(tcph->source));
	sprintf(tmp2, "dest port %lu", (unsigned int)ntohs(tcph->dest));

	sprintf(entry1, entry1_format, print_centre(tmp1, col_s), print_centre(tmp2, col_d));

	memset(&tmp1, 0, sizeof(tmp1));
	memset(&tmp2, 0, sizeof(tmp2));

	unsigned int tcpack = ntohl(tcph->th_ack);
	unsigned int seq = ntohl(tcph->th_seq);
	sprintf(tmp1, "seq no %lu", (unsigned int)seq);
	sprintf(entry2, entry2_format, print_centre(tmp1, col_seq));

	sprintf(tmp2, "ack no %lu", (unsigned int)tcpack);
	sprintf(entry3, entry3_format, print_centre(tmp2, col_acks));

	memset(&tmp1, 0, sizeof(tmp1));
	memset(&tmp2, 0, sizeof(tmp2));

	char tmp3[MAX_BUFFER_SIZE];
	char tmp4[MAX_BUFFER_SIZE];
	char tmp5[MAX_BUFFER_SIZE];
	char tmp6[MAX_BUFFER_SIZE];
	char tmp7[MAX_BUFFER_SIZE];
	char tmp8[MAX_BUFFER_SIZE];
	char tmp9[MAX_BUFFER_SIZE];
	sprintf(tmp1, "header len %lu", (unsigned int)tcph->doff * 4);
	sprintf(tmp2, "rb %lu%lu", (unsigned int)tcph->res1, (unsigned int)tcph->res2);
	sprintf(tmp3, "urg %lu", (unsigned int)tcph->urg);
	sprintf(tmp4, "ack %lu", (unsigned int)tcph->ack);
	sprintf(tmp5, "psh %lu", (unsigned int)tcph->psh);
	sprintf(tmp6, "rst %lu", (unsigned int)tcph->rst);
	sprintf(tmp7, "syn %lu", (unsigned int)tcph->syn);
	sprintf(tmp8, "fin %lu", (unsigned int)tcph->fin);
	sprintf(tmp9, "win size %lu", ntohs(tcph->window));

	sprintf(entry4, entry4_format, print_centre(tmp1, col_hdl), print_centre(tmp2, col_rb), print_centre(tmp3, col_urg), print_centre(tmp4, col_ack), print_centre(tmp5, col_psh), print_centre(tmp6, col_rst), print_centre(tmp7, col_syn), print_centre(tmp8, col_fin), print_centre(tmp9, col_win));

	memset(&tmp1, 0, sizeof(tmp1));
	memset(&tmp2, 0, sizeof(tmp2));

	sprintf(tmp1, "checksum %lu", ntohs(tcph->check));
	sprintf(tmp2, "urgent ptr %hu", tcph->urg_ptr);

	sprintf(entry5, entry5_format, print_centre(tmp1, col_cs), print_centre(tmp2, col_up));

	char **entries = (char **)calloc(5, sizeof(char *));
	entries[0] = entry1;
	entries[1] = entry2;
	entries[2] = entry3;
	entries[3] = entry4;
	entries[4] = entry5;

	return entries;
}