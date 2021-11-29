#pragma once

#include <menu.h>
#include "windows.h"

MENU * get_device_menu(int row_len);
void device_menu_handler(WIN *win);
void set_attr(WIN *win,chtype col,chtype col2);
void chosen(char * name,WIN * win);
MENU *get_capture_menu(int row_len);
void capture_menu_handler(WIN *win);
int getCur();
void packetChosen(char * name, WIN *win);
void packet_handler(WIN * win,char ** packets,int size);
void open_pcap_file(char *name);
void info_handler(WIN *win);
void show_info(WIN *win);