#ifndef MYSQL_DRIVER_TCP_MANAGER_H
#define MYSQL_DRIVER_TCP_MANAGER_H

#include <winsock.h>
#include <stdbool.h>

typedef struct {
    unsigned int payload_len;
    unsigned char seq_id;
    unsigned char* payload;
    int total_recv;
    bool error;
} mysql_packet_t;

int tcp_connect(char* host, int port, SOCKET* sock);
mysql_packet_t tcp_read_socket_response(SOCKET sock);
int tcp_send_packet(SOCKET sock, unsigned char seq_id, unsigned char* payload, int payload_len);

#endif //MYSQL_DRIVER_TCP_MANAGER_H
