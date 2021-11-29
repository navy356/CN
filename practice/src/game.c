#include <ncurses.h>
#include <stdlib.h>
#include <string.h>

#include "game.h"
WINDOW *wnd;
typedef struct
{
    uint_fast8_t x;
    uint_fast8_t y;
} vec2ui;

typedef struct
{
    int_fast8_t x;
    int_fast8_t y;
} vec2i;

struct
{
    vec2i pos;
    char disp_char;
} player;

vec2i initPos(int_fast8_t x, int_fast8_t y)
{
    vec2i pos;
    pos.x = x;
    pos.y = y;
    return pos;
}
int init()
{
    wnd = initscr();
    cbreak();
    noecho();
    keypad(wnd, true);
    //nodelay(wnd, true);
    curs_set(0);

    if (!has_colors())
    {
        endwin();
        printf("ERROR: Terminal does not support color.\n");
        exit(1);
    }

    start_color();

    init_pair(1, 231, 161);
    wbkgd(wnd, COLOR_PAIR(1));

    clear();

    wattron(wnd,A_BOLD);
    box(wnd, 0, 0);
    wattroff(wnd,A_BOLD);
    refresh();

    return 0;
}

void run()
{
    player.disp_char = '0';
    player.pos = initPos(10, 5);

    mvaddch(player.pos.y, player.pos.x, player.disp_char);
    refresh();

    int in_char;

    bool exit_requested = false;

    while(1) {
        in_char = wgetch(wnd);
        mvaddch(player.pos.y, player.pos.x, ' ');
        
        switch(in_char) {
            case 'q':
                exit_requested = true;
                break;
            case KEY_UP:
            case 'w':
                player.pos.y -= 1;
                break;
            case KEY_DOWN:
            case 's':
                player.pos.y += 1;
                break;
            case KEY_LEFT:
            case 'a':
                player.pos.x -= 1;
                break;
            case KEY_RIGHT:
            case 'd':
                player.pos.x += 1;
                break;
            default:
                break;
        }

        mvaddch(player.pos.y, player.pos.x, player.disp_char);
        refresh();

        if(exit_requested) break;
    }
}

void close()
{
    endwin();
}

int main(int argc, char **argv)
{
    int init_status = init();

    if (init_status == 0)
        run();

    close();

    return 0;
}
