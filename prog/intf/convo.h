#include <pcap.h>

typedef struct node_c NODEC,*NODEC_PTR;
struct node_c {
   int key;
   char * source;
   char * destination;
   uint16_t sport;
   uint16_t dport;
   int finish;
   NODEC_PTR next;
};

void displayNodec(NODEC_PTR * head,int key);
void insertc(NODEC_PTR * head,int key, char * source, char * destination, uint16_t sport, uint16_t dport);
NODEC_PTR getNodec(NODEC_PTR * head, int key);
NODEC_PTR init_listc();
int getLenc(NODEC_PTR * head);
int findKeyc(NODEC_PTR * head, char * source, char * dest, uint16_t sport, uint16_t dport);
void setFinishc(NODEC_PTR * head, int key);