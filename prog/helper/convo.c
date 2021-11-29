#include "convo.h"
#include <string.h>
#include <stdlib.h>

NODEC_PTR init_listc()
{
    NODEC_PTR head = (NODEC_PTR)malloc(sizeof(NODEC));
    head->key = 0;
    head->source = NULL;
    head->destination = NULL;
    head->sport = 0;
    head->dport = 0;
    head->next = NULL;
    head->finish = 0;
}

int getLenc(NODEC_PTR * head)
{
    NODEC_PTR tmp = *head;
    return tmp->key;
}

NODEC_PTR create_nodec(int key, char * source, char * destination,uint16_t sport, uint16_t dport)
{
    NODEC_PTR node = (NODEC_PTR)malloc(sizeof(NODEC));
    node->key = key;
    node->source = (char *)calloc(20,sizeof(char));
    node->destination = (char *)calloc(20,sizeof(char));
    node->sport = sport;
    node->dport = dport;
    strcpy(node->source,source);
    strcpy(node->destination,destination);
    node->next = NULL;
    node->finish = 0;

    return node;
}

void insertc(NODEC_PTR * head,int key, char * source, char * destination,uint16_t sport, uint16_t dport)
{
    NODEC_PTR tmp = *head;
    tmp->key=tmp->key+1;
    while(tmp->next!=NULL)
        tmp=tmp->next;

    NODEC_PTR node = create_nodec(key,source, destination, sport, dport);
    tmp->next = node;
}

NODEC_PTR getNodec(NODEC_PTR * head, int key)
{
    NODEC_PTR tmp = *head;
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

int findKeyc(NODEC_PTR * head, char * source, char * dest, uint16_t sport, uint16_t dport)
{
    NODEC_PTR tmp = *head;
    if(tmp->next == NULL)
        return -1;
    else
        tmp = tmp->next;

    while(tmp!=NULL)
    {
        if((strcmp(source,tmp->source)==0) && (strcmp(dest,tmp->destination)==0) && (tmp->sport==sport) && (tmp->dport==dport) && (tmp->finish==0))
        {
            return tmp->key;
        }
        tmp=tmp->next;
    }

    return -1;
}

void setFinishc(NODEC_PTR * head, int key)
{
    NODEC_PTR tmp = getNodec(head,key);
    tmp->finish = 1;
}

void displayNodec(NODEC_PTR * head,int key)
{
    NODEC_PTR node = getNodec(head,key);
    printf("%d\n",node->key);
    puts(node->source);
    puts(node->destination);
    printf("%d\n",node->sport);
    printf("%d\n",node->dport);
}