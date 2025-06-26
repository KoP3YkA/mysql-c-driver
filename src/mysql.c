#include "../include/structures.h"
#include "../include/handshake_manager.h"
#include <stdbool.h>
#include <stdio.h>
#include <winsock2.h>

mysql_connection_t mysql_driver_connect(mysql_connection_data data) {
    SOCKET sock;
    int result = mysql_driver_net_handshake(data, &sock);

    if (result != 0) {
        char* message = NULL;

        if (result == 1) message = "Opening TCP:WSAStartup failed";
        else if (result == 2) message = "Opening TCP:Invalid socket";
        else if (result == 3) message = "Opening TCP:Socket error";
        else if (result == 4) message = "Opening TCP:INADDR_NONE";
        else if (result == 5) message = "Reading handshake:Invalid header";
        else if (result == 6) message = "Reading handshake:Payload is null";
        else if (result == 7) message = "Reading handshake:recv result is invalid";
        else if (result == 207) message = "Sending response handshake packet:TCP freaked out";
        else if (result == 307) message = "Sending response handshake packet:out header is invalid";
        else if (result == 308) message = "Sending response handshake packet:TCP freaked out #2";
        else {
            char buffer[128];
            snprintf(buffer, sizeof(buffer), "Sending response handshake packet:Undefined error:%d", result);
            message = strdup(buffer);
        }

        mysql_connection_t res = {0};
        res.status = false;
        res.sock = INVALID_SOCKET;

        if (message != NULL && result < 200) {
            res.message = strdup(message);
        } else {
            res.message = message;
        }

        return res;
    }

    mysql_connection_t res = { true, NULL, sock };
    return res;
}