#include "devices.h"
#include <pcap.h>
#include "constants.h"
#include <menu.h>
#include "utility.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

pcap_if_t *alldevsp;
char errbuf[MAX_BUFFER_SIZE];
char devs[MAX_DEVICES][MAX_BUFFER_SIZE];

void init_devices()
{
    if (pcap_findalldevs(&alldevsp, errbuf))
    {
        //fix later
        printf("Error finding devices : %s", errbuf);
        exit(1);
    }
    pcap_if_t *device;
    int count = 1;
    for (device = alldevsp; device != NULL; device = device->next)
    {
        if (device->name != NULL)
        {
            strcpy(devs[count], device->name);
        }
        count++;
    }
}

ITEM ** device_menu_entry(int row_len)
{
    ITEM ** items = (ITEM**)calloc(MAX_DEVICES+1,sizeof(ITEM *));
    pcap_if_t *device;
    int count = 0;
    if(row_len<MIN_ENTRY_SIZE)
    {
        row_len = MIN_ENTRY_SIZE;
    }
    int col2 = getPercentageInt(40,row_len);
    int col3 = getPercentageInt(60,row_len);
    char entry_format[MAX_BUFFER_SIZE];
    char desc_format[MAX_BUFFER_SIZE];
    sprintf(entry_format,"%%-%d.%ds",col2,col2);
    sprintf(desc_format,"%%-%d.%ds",col3,col3);
    for(device = alldevsp; device != NULL; device = device->next)
    {
        char * entry = (char *)calloc(MAX_BUFFER_SIZE,sizeof(char));
        char * desc = (char *)calloc(MAX_BUFFER_SIZE,sizeof(char));
        sprintf(entry,entry_format,device->name);
        sprintf(desc,desc_format,device->description);
        items[count]=new_item(entry,desc);
        count++;
    }
    items[count]=(ITEM *)NULL;
    return items;
}

char * device_menu_header(int row_len)
{
    if(row_len<MIN_ENTRY_SIZE)
    {
        row_len = MIN_ENTRY_SIZE;
    }
    int col2 = getPercentageInt(40,row_len);
    int col3 = getPercentageInt(60,row_len);
    char entry_format[MAX_BUFFER_SIZE];
    sprintf(entry_format,"   %%-%d.%ds     %%-%d.%ds",col2-4,col2-4,col3-4,col3-4);
    char * entry = (char *)calloc(MAX_BUFFER_SIZE,sizeof(char));
    sprintf(entry,entry_format,"Device name","Description");
    return entry;
}