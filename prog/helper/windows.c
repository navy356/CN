#include <ncurses.h>
#include <menu.h>
#include "windows.h"
#include "menu_u.h"
#include "devices.h"
#include "utility.h"
#include "string.h"
#include <locale.h>
#include "sniffer.h"
#include "constants.h"

WINDOW *wnd;

void init_windows(char *file)
{
    wnd = initscr();
    setlocale(LC_ALL, "");
    cbreak();
    noecho();
    keypad(wnd, true);
    curs_set(0);

    if (!has_colors())
    {
        endwin();
        printf("ERROR: Terminal does not support color.\n");
        exit(1);
    }

    start_color();

    init_pair(1, 231, 161);
    init_pair(2, 161, 231);
    init_pair(3, 161, 252);
    wbkgd(wnd, COLOR_PAIR(1));

    clear();

    wrefresh(wnd);

    if (file == NULL)
    {
        int h;
        int w;
        getmaxyx(wnd, h, w);
        WIN *dev_window = getDeviceWindow(0, 0, h, w);
        postWin(dev_window);
        postDevHeader(dev_window);
        device_menu_handler(dev_window);
    }
    else
    {
        open_pcap_file(file);
    }
}

WINDOW *getWin()
{
    return wnd;
}

void postWin(WIN *win)
{
    set_menu_mark(win->menu, " * ");
    set_attr(win, COLOR_PAIR(1), COLOR_PAIR(2));
    wbkgd(win->menuw, COLOR_PAIR(1));
    wclear(win->menuw);
    wattron(win->menuw, COLOR_PAIR(1));
    box(win->menuw, 0, 0);
    wattroff(win->menuw, COLOR_PAIR(1));
    post_menu(win->menu);
    wrefresh(win->menuw);
}

WIN *getDeviceWindow(int x, int y, int h, int w)
{
    WINDOW *dev_win = newwin(h, w, y, x);
    int offsetY = getPercentageInt(18, h);
    int offsetX = getPercentageInt(2.5, w);
    MENU *dev_menu = get_device_menu(w - offsetX * 2);
    set_menu_win(dev_menu, dev_win);
    WINDOW *submenu = derwin(dev_win, h - offsetY * 2, w - offsetX * 2, offsetY, offsetX);
    set_menu_format(dev_menu, h - offsetY * 2, 1);
    set_menu_sub(dev_menu, submenu);
    WIN *dev = (WIN *)malloc(sizeof(WIN));
    dev->menuw = dev_win;
    dev->sub_menuw = submenu;
    dev->menu = dev_menu;

    return dev;
}

WIN *getCaptureWindow(int x, int y, int h, int w)
{
    WINDOW *cap_win = newwin(h, w, y, x);
    int offsetY = getPercentageInt(18, h);
    int offsetX = getPercentageInt(2.5, w);
    MENU *cap_menu = get_capture_menu(w - offsetX * 2);
    set_menu_win(cap_menu, cap_win);
    WINDOW *submenu = derwin(cap_win, h - offsetY * 2, w - offsetX * 2, offsetY, offsetX);
    set_menu_sub(cap_menu, submenu);
    set_menu_format(cap_menu, h - offsetY * 2, 1);
    WIN *cap = (WIN *)malloc(sizeof(WIN));
    cap->menuw = cap_win;
    cap->sub_menuw = submenu;
    cap->menu = cap_menu;

    return cap;
}

WIN *getPacketWindow(int x, int y, int h, int w)
{
    WINDOW *cap_win = newwin(h, w, y, x);
    int offsetY = getPercentageInt(18, h);
    int offsetX = getPercentageInt(2.5, w);
    WINDOW *subwin = derwin(cap_win, h - offsetY * 2, w - offsetX * 2, offsetY, offsetX);
    WIN *cap = (WIN *)malloc(sizeof(WIN));
    cap->menuw = cap_win;
    cap->sub_menuw = subwin;
    cap->menu = NULL;

    return cap;
}

WIN *getInfoWindow(int x, int y, int h, int w)
{
    WINDOW *info_win = newwin(h, w, y, x);
    int offsetY = getPercentageInt(18, h);
    int offsetX = getPercentageInt(2.5, w);
    WINDOW *subwin = derwin(info_win, h - offsetY * 2, w - offsetX * 2, offsetY, offsetX);
    WIN *info = (WIN *)malloc(sizeof(WIN));
    info->menuw = info_win;
    info->sub_menuw = subwin;
    info->menu = NULL;

    return info;
}


void updatePacketWindow(WIN *win, char **packet, int size, int y)
{
    keypad(win->menuw, true);
    wbkgd(win->menuw, COLOR_PAIR(1));
    wbkgd(win->sub_menuw, COLOR_PAIR(1));
    wclear(win->menuw);
    wattron(win->menuw, COLOR_PAIR(1));
    box(win->menuw, 0, 0);
    print_packet(win, packet, size, y);
    box(win->sub_menuw, 0, 0);
    wattroff(win->menuw, COLOR_PAIR(1));
    wrefresh(win->menuw);
}

void updateInfoWindow(WIN *win, char **info)
{
    keypad(win->menuw, true);
    wbkgd(win->menuw, COLOR_PAIR(1));
    wbkgd(win->sub_menuw, COLOR_PAIR(1));
    wclear(win->menuw);
    wattron(win->menuw, COLOR_PAIR(1));
    box(win->menuw, 0, 0);
    mvwprintw(win->sub_menuw,0,0,info[0]);
    mvwprintw(win->sub_menuw,1,0,info[1]);
    mvwprintw(win->sub_menuw,2,0,info[2]);
    wattroff(win->menuw, COLOR_PAIR(1));
    wrefresh(win->menuw);
}

void print_packet(WIN *win, char **packet, int size, int start)
{
    int h;
    int w;
    wmove(win->sub_menuw, 1, 1);
    getmaxyx(win->sub_menuw, h, w);
    if (start >= h)
    {
        start = start - h;
    }
    if (start < 0)
    {
        start = 0;
    }
    for (int i = start; i < size; i++)
    {
        int x;
        int y;
        int y_tmp;

        getyx(win->sub_menuw, y_tmp, x);
        if (packet[i] != NULL)
        {
            wattron(win->menuw, COLOR_PAIR(1));
            wprintw(win->sub_menuw, packet[i]);
            wattroff(win->menuw, COLOR_PAIR(1));
        }

        getyx(win->sub_menuw, y, x);
        wattron(win->menuw, COLOR_PAIR(1));
        if (y == y_tmp)
        {
            wmove(win->sub_menuw, y + 1, 0);
            y = y + 1;
        }
        else
        {
            wmove(win->sub_menuw, y, 0);
        }
        whline(win->sub_menuw, '-', getmaxx(win->sub_menuw));
        wattroff(win->menuw, COLOR_PAIR(1));
        if (y >= h)
        {
            return;
        }
        wmove(win->sub_menuw, y + 1, getbegx(win->sub_menuw));
    }
}

void print_in_middle(WINDOW *win, char *string, chtype color)
{
    int length, x, y;
    float temp;

    getyx(win, y, x);
    x = 0;

    int width = win->_maxx;

    length = strlen(string);
    temp = (width - length) / 2;
    x = x + (int)temp;
    wattron(win, color);
    mvwprintw(win, y, x, "%s", string);
    wattroff(win, color);
    wrefresh(win);
}

void postDevHeader(WIN *win)
{
    int h, w;
    getmaxyx(win->menuw, h, w);
    int offsetY = getPercentageInt(7.5, h);
    int offsetX = getPercentageInt(2.5, w);
    wmove(win->menuw, 0, 0);
    wattron(win->menuw, COLOR_PAIR(1));
    mvwprintw(win->menuw, offsetY, offsetX, device_menu_header(w - offsetX * 2));
    wattroff(win->menuw, COLOR_PAIR(1));
    wmove(win->menuw, offsetY * 2, 0);
    whline(win->menuw, ACS_HLINE, w);
    box(win->menuw, 0, 0);
    wrefresh(win->menuw);
}

void postCapHeader(WIN *win)
{
    int h, w;
    getmaxyx(win->menuw, h, w);
    int offsetY = getPercentageInt(7.5, h);
    int offsetX = getPercentageInt(2.5, w);
    wmove(win->menuw, 0, 0);
    wattron(win->menuw, COLOR_PAIR(1));
    mvwprintw(win->menuw, offsetY, offsetX, packet_menu_header(w - offsetX * 2));
    wattroff(win->menuw, COLOR_PAIR(1));
    wmove(win->menuw, offsetY * 2, 0);
    whline(win->menuw, ACS_HLINE, w);
    box(win->menuw, 0, 0);
    wrefresh(win->menuw);
}

void updateCapWin(WIN *cap_win)
{
    int h, w;
    getmaxyx(cap_win->menuw, h, w);
    int offsetY = getPercentageInt(18, h);
    int offsetX = getPercentageInt(2.5, w);
    ITEM **items = packet_menu_entry(w - 2 * offsetX);
    unpost_menu(cap_win->menu);
    set_menu_items(cap_win->menu, items);
    set_menu_format(cap_win->menu, h - offsetY * 2, 1);
    if (getCur() > 0)
        set_current_item(cap_win->menu, items[getCur()]);
    postWin(cap_win);
    postCapHeader(cap_win);
}