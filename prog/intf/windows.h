#pragma once
#include <ncurses.h>
#include <stdlib.h>
#include <menu.h>

typedef struct win WIN;
struct win
{
    WINDOW *menuw;
    WINDOW *sub_menuw;
    MENU *menu;
};

WINDOW * getWin();
void init_windows(char * file);
void print_in_middle(WINDOW *win, char *string, chtype color);
void postWin(WIN * win);
void postDevHeader(WIN * win);
WIN *getDeviceWindow(int x, int y, int h, int w);
WIN *getCaptureWindow(int x, int y, int h, int w);
void updateCapWin(WIN * cap_win);
void postCapHeader(WIN * win);
WIN *getPacketWindow(int x, int y, int h, int w);
void updatePacketWindow(WIN * win, char ** packet,int size,int y);
void print_packet(WIN * win, char ** packet, int size,int y);
void updateInfoWindow(WIN *win, char **info);
WIN *getInfoWindow(int x, int y, int h, int w);