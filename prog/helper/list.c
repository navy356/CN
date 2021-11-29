#include "list.h"
#include "constants.h"
#include <string.h>
#include <stdlib.h>

NODE_PTR init_list()
{
    NODE_PTR head = (NODE_PTR)malloc(sizeof(NODE));
    head->key = 0;
    head->header = NULL;
    head->buffer = NULL;
    head->source = NULL;
    head->destination = NULL;
    head->protocol = NULL;
    head->info = NULL;
    head->next = NULL;
    head->convo = -1;
}

int getLen(NODE_PTR * head)
{
    NODE_PTR tmp = *head;
    return tmp->key;
}

NODE_PTR create_node(int key, const struct pcap_pkthdr *header, const u_char *buffer, char * source, char * destination,char * protocol,char * info, int convo)
{
    NODE_PTR node = (NODE_PTR)malloc(sizeof(NODE));
    node->key = key;
    node->header = header;

    node->buffer = (char *)calloc(MAX_BUFFER_SIZE,sizeof(u_char));
    node->source = (char *)calloc(20,sizeof(char));
    node->destination = (char *)calloc(20,sizeof(char));
    node->protocol = (char *)calloc(10,sizeof(char));
    node->info = (char *)calloc(MAX_BUFFER_SIZE,sizeof(char));
    node->convo = convo;

    node->buffer=buffer;
    strcpy(node->info,"");
    strcpy(node->source,source);
    strcpy(node->destination,destination);
    strcpy(node->protocol,protocol);
    strcpy(node->info,info);

    node->next = NULL;

    return node;
}

void insert(NODE_PTR * head,int key, const struct pcap_pkthdr *header, const u_char *buffer, char * source, char * destination,char * protocol,char * info, int convo)
{
    NODE_PTR tmp = *head;
    tmp->key=tmp->key+1;
    while(tmp->next!=NULL)
        tmp=tmp->next;

    NODE_PTR node = create_node(key, header, buffer, source, destination, protocol, info,convo);
    tmp->next = node;
}

NODE_PTR getNode(NODE_PTR * head, int key)
{
    NODE_PTR tmp = *head;
    if(tmp->next == NULL)
        return NULL;
    else
        tmp = tmp->next;

    while(tmp!=NULL)
    {
        if(tmp->key==key)
            return tmp;
        tmp=tmp->next;
    }

    return tmp;
}

NODE_PTR find_convo(NODE_PTR * head, int convo)
{
    NODE_PTR convo_ptr=init_list();
    NODE_PTR tmp = *head;
    if(tmp->next == NULL)
        return NULL;
    else
        tmp = tmp->next;

    while(tmp!=NULL)
    {
        if(tmp->convo==convo)
        {
            insert(&convo_ptr,tmp->key,tmp->header,tmp->buffer,tmp->source,tmp->destination,tmp->protocol,tmp->info,tmp->convo);
        }
        tmp=tmp->next;
    }

    return convo_ptr;
}

void updateInfo(NODE_PTR * head,int key,char * info)
{
    if(finishedInfo(head,key)==1)
    {
        return;
    }
    NODE_PTR tmp = getNode(head,key);
    if(tmp==NULL)
    {
        return;
    }
    if(strcmp(tmp->info,"")==0)
    {
        strcpy(tmp->info,info);
    }
    else
    {   
        tmp->info = strcat(tmp->info,info);
    }
}

int finishedInfo(NODE_PTR * head,int key)
{
    NODE_PTR tmp = getNode(head,key);
    if(tmp==NULL)
    {
        return 0;
    }
    int l = strlen(tmp->info);
    if(tmp->info[l-1]=='~')
    {
        return 1;
    }
    else
    {   
        return 0;
    }
}

void displayNode(NODE_PTR * head,int key)
{
    NODE_PTR node = getNode(head,key);
    printf("%d\n",node->key);
    puts(node->source);
    puts(node->destination);
    puts(node->info);
    puts(node->protocol);
    printf("%d\n",node->convo);
}