#include <menu.h>
#include "devices.h"
#include "menu_u.h"
#include "utility.h"
#include "windows.h"
#include <ctype.h>
#include "sniffer.h"

int cur = 0;
MENU *get_device_menu(int row_len)
{
    ITEM **items = device_menu_entry(row_len);
    MENU *dev_menu = new_menu((ITEM **)items);
    return dev_menu;
}

MENU *get_capture_menu(int row_len)
{
    ITEM **items = packet_menu_entry(row_len);
    MENU *cap_menu = new_menu((ITEM **)items);
    return cap_menu;
}

void device_menu_handler(WIN *win)
{
    int c;
    while (((c = wgetch(win->menuw)) != KEY_F(1)))
    {
        switch (c)
        {
        case KEY_DOWN:
            menu_driver(win->menu, REQ_DOWN_ITEM);
            break;
        case KEY_UP:
            menu_driver(win->menu, REQ_UP_ITEM);
            break;
        case KEY_NPAGE:
            menu_driver(win->menu, REQ_SCR_DPAGE);
            break;
        case KEY_PPAGE:
            menu_driver(win->menu, REQ_SCR_UPAGE);
            break;
        case 10: /* Enter */
        {
            ITEM *cur;
            void (*p)(char *);

            cur = current_item(win->menu);
            chosen((char *)item_name(cur), win);
            pos_menu_cursor(win->menu);
            return;
        }
        }
        wrefresh(win->menuw);
    }
}

void capture_menu_handler(WIN *win)
{
    int c;
    while (((c = wgetch(win->menuw)) != KEY_F(1)))
    {
        switch (c)
        {
            ITEM *cur_item;
        case KEY_DOWN:
            menu_driver(win->menu, REQ_DOWN_ITEM);
            cur_item = current_item(win->menu);
            cur = item_index(cur_item);
            wrefresh(win->menuw);
            break;
        case KEY_UP:
            menu_driver(win->menu, REQ_UP_ITEM);
            cur_item = current_item(win->menu);
            cur = item_index(cur_item);
            wrefresh(win->menuw);
            break;
        case KEY_NPAGE:
            menu_driver(win->menu, REQ_SCR_DPAGE);
            cur_item = current_item(win->menu);
            cur = item_index(cur_item);
            wrefresh(win->menuw);
            break;
        case KEY_PPAGE:
            menu_driver(win->menu, REQ_SCR_UPAGE);
            cur_item = current_item(win->menu);
            cur = item_index(cur_item);
            wrefresh(win->menuw);
            break;
        case 10: /* Enter */
        {
            ITEM *cur;
            void (*p)(char *);

            cur = current_item(win->menu);
            packetChosen((char *)item_name(cur), win);
            pos_menu_cursor(win->menu);
            wclear(win->menuw);
            updateCapWin(win);
            wrefresh(win->menuw);
        }
        }
        wrefresh(win->menuw);
    }
}

int getCur()
{
    return cur;
}

void set_attr(WIN *win, chtype col1, chtype col2)
{
    set_menu_back(win->menu, col1);
    set_menu_fore(win->menu, col2);
    set_menu_grey(win->menu, col1);
    keypad(win->menuw, true);
}

void chosen(char *name, WIN *win)
{
    int h, w;
    getmaxyx(getWin(), h, w);
    WIN *cap_window = getCaptureWindow(0, 0, h, w);
    updateCapWin(cap_window);
    name = trim(name);
    start_capture(name, cap_window);
    wclear(win->menuw);
    capture_menu_handler(cap_window);
}

void packet_handler(WIN *win, char **packets, int size)
{
    int c;
    int start = 0;
    int h, w;
    getmaxyx(win->sub_menuw, h, w);
    while (((c = wgetch(win->menuw)) != KEY_F(1)))
    {
        switch (c)
        {
            ITEM *cur_item;
        case KEY_DOWN:
        case KEY_NPAGE:
            start++;
            if (start >= h)
            {
                start = start - h;
            }
            updatePacketWindow(win,packets,size,start);
            break;
        case KEY_UP:
        case KEY_PPAGE:
            start--;
            if (start < 0)
            {
                start = 0;
            }
            updatePacketWindow(win, packets, size, start);
            break;
        case 10: /* Enter */
            return;
        }
    }
}

void packetChosen(char *name, WIN *win)
{
    int h, w;
    getmaxyx(getWin(), h, w);
    int offsetY = getPercentageInt(18, h);
    int offsetX = getPercentageInt(2.5, w);
    setDisable(1);
    name = trim(name);
    int n = atoi(name);
    WIN *packet_window = getPacketWindow(0, 0, h, w);
    int size = 14;
    char **packets = (char **)malloc(sizeof(char *) * size);
    packets[0] = print_centre("Ethernet Header", w - 2 * offsetX);
    packets[1] = get_ethernet_header(n, w - 2 * offsetX);
    packets[2] = print_centre("IP Header", w - 2 * offsetX);
    char **ip = get_ipv4_header(n, w - 2 * offsetX);
    for (int i = 0; i < 5; i++)
    {
        packets[3 + i] = ip[i];
    }
    packets[8] = print_centre("TCP Header", w - 2 * offsetX);
    char **tcp = get_tcp_packet(n, w - 2 * offsetX);
    for (int i = 0; i < 5; i++)
    {
        packets[9 + i] = tcp[i];
    }
    updatePacketWindow(packet_window, packets, size, 0);
    packet_handler(packet_window, packets, size);
    setDisable(0);
}