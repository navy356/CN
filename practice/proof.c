#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
void clean_exit_on_sig(int sig_num)
{
    printf("\n Signal %d received", sig_num);
    exit(1);
}

int main()
{
    int A[100];
    signal(SIGINT, clean_exit_on_sig);
    signal(SIGABRT, clean_exit_on_sig);
    signal(SIGILL, clean_exit_on_sig);
    signal(SIGFPE, clean_exit_on_sig);
    signal(SIGSEGV, clean_exit_on_sig); // <-- this one is for segmentation fault
    signal(SIGTERM, clean_exit_on_sig);

    int *p;
    memcpy(&p, "AAAAAAAA", 8);
    int a = *p;
}
