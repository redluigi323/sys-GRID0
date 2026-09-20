#pragma once
/* MiniSSDPd's optional Unix-domain path is unavailable on Horizon. Its
 * connection fails normally; SSDP UDP discovery then runs instead. */
#include <sys/socket.h>
struct sockaddr_un {
    sa_family_t sun_family;
    char sun_path[108];
};
