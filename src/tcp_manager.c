#include <winsock.h>
#include "../include/tcp_manager.h"

int tcp_connect(char* host, int port, SOCKET* sock) {
    WSADATA wsadata;

    if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
        return 1; // WSAStartup failed
    }

    *sock = socket(PF_INET, SOCK_STREAM, 0);
    if (*sock == INVALID_SOCKET) {
        WSACleanup();
        return 2; // Invalid socket
    }

    SOCKADDR_IN sock_address;
    memset(&sock_address, 0, sizeof(sock_address));

    sock_address.sin_family = AF_INET;
    sock_address.sin_port = htons(port);

    unsigned long addr = inet_addr(host);
    if (addr == INADDR_NONE) {
        closesocket(*sock);
        WSACleanup();
        return 4; // Inaddr none
    }

    sock_address.sin_addr.s_addr = addr;

    int result = connect(*sock, (SOCKADDR*) &sock_address, sizeof(sock_address));

    if (result == SOCKET_ERROR) {
        closesocket(*sock);
        WSACleanup();
        return 3; // Socket error
    }

    return 0;
}

mysql_packet_t tcp_read_socket_response(SOCKET sock) {
    mysql_packet_t packet = {0};

    unsigned char header[4];
    int rec = recv(sock, (char*)header, 4, 0);
    if (rec != 4) {
        packet.error = true;
        return packet;
    }

    packet.payload_len = header[0] | (header[1] << 8) | (header[2] << 16);
    packet.seq_id = header[3];

    packet.payload = malloc(packet.payload_len);
    if (packet.payload == NULL) {
        packet.error = true;
        return packet;
    }

    int total_recv = 0;
    while (total_recv < packet.payload_len) {
        int r = recv(sock, (char*)packet.payload + total_recv, packet.payload_len - total_recv, 0);
        if (r <= 0) {
            free(packet.payload);
            packet.payload = NULL;
            packet.error = true;
            return packet;
        }
        total_recv += r;
    }

    packet.total_recv = total_recv;
    packet.error = false;
    return packet;
}

int tcp_send_packet(SOCKET sock, unsigned char seq_id, unsigned char* payload, int payload_len) {
    unsigned char header[4];
    header[0] = payload_len & 0xFF;
    header[1] = (payload_len >> 8) & 0xFF;
    header[2] = (payload_len >> 16) & 0xFF;
    header[3] = seq_id;

    int total_sent = 0;
    while (total_sent < 4) {
        int sent = send(sock, (char*)header + total_sent, 4 - total_sent, 0);
        if (sent <= 0) return 1;
        total_sent += sent;
    }

    total_sent = 0;
    while (total_sent < payload_len) {
        int sent = send(sock, (char*)payload + total_sent, payload_len - total_sent, 0);
        if (sent <= 0) return 2;
        total_sent += sent;
    }

    return 0;
}