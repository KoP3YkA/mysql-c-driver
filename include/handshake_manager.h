#ifndef MYSQL_DRIVER_HANDSHAKE_MANAGER_H
#define MYSQL_DRIVER_HANDSHAKE_MANAGER_H

#include <winsock.h>
#include "structures.h"

int mysql_driver_net_handshake(mysql_connection_data connection_data, SOCKET* out_socket);

#endif //MYSQL_DRIVER_HANDSHAKE_MANAGER_H
