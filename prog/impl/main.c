#include "init.h"
#include "devices.h"
#include "utility.h"
#include "list.h"
#include "sniffer.h"
#include <signal.h>

void INThandler(int);

void INThandler(int x)
{
    endwin();
    exit(0);
}
int main(int argc, char **argv)
{
    char * file = NULL;
    if(argc>1)
    {
        file = argv[1];
    }
    signal(SIGSEGV, INThandler);
    signal(SIGABRT, INThandler);
    signal(SIGINT, INThandler);
    signal(SIGTRAP, INThandler);
    init(file);
    while(1);
    /*init_sniffer();
    start_capture("wlo1",NULL);
    while(1);*/
}