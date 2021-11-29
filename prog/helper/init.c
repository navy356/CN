#include "init.h"
#include "windows.h"
#include "devices.h"
#include "sniffer.h"

void init()
{
    init_sniffer();
    init_devices();
    init_windows();
}