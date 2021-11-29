#pragma once

#include <pcap.h>
#include <menu.h>
void init_devices();
char * device_menu_header(int row_len);
ITEM ** device_menu_entry(int row_len);