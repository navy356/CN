#include "init.h"
#include "windows.h"
#include "devices.h"
#include "sniffer.h"

void init(char * file)
{
    init_sniffer();
    init_devices();
    init_windows(file);
}