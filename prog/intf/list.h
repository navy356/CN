#include <pcap.h>

typedef struct node NODE,*NODE_PTR;
struct node {
   int key;
   const struct pcap_pkthdr *header;
   const u_char *buffer;
   char * source;
   char * destination;
   char * protocol;
   char * info;
   int convo;
   NODE_PTR next;
};

void displayNode(NODE_PTR * head,int key);
void insert(NODE_PTR * head,int key, const struct pcap_pkthdr *header,  const u_char *buffer, char * source, char * destination,char * protocol,char * info, int convo);
NODE_PTR getNode(NODE_PTR * head, int key);
NODE_PTR init_list();
int getLen(NODE_PTR * head);
NODE_PTR find_convo(NODE_PTR * head, int convo);
void updateInfo(NODE_PTR * head,int key,char * info);
int finishedInfo(NODE_PTR * head,int key);