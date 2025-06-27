#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <stdint.h>
#include "../include/structures.h"
#include "../libs/sha256.h"
#include "../include/tcp_manager.h"

#define CLIENT_LONG_PASSWORD     0x00000001
#define CLIENT_FOUND_ROWS        0x00000002
#define CLIENT_LONG_FLAG         0x00000004
#define CLIENT_CONNECT_WITH_DB   0x00000008
#define CLIENT_PROTOCOL_41       0x00000200
#define CLIENT_SECURE_CONNECTION 0x00008000
#define CLIENT_PLUGIN_AUTH       0x00080000

int mysql_driver_read_handshake(SOCKET sock, mysql_server_handshake_data* data) {
    mysql_packet_t packet = tcp_read_socket_response(sock);
    if (packet.error) {
        return 1;
    }

    unsigned int payload_len = packet.payload_len;
    unsigned char seq_id = packet.seq_id;

    unsigned char* payload = malloc(payload_len);
    if (payload == NULL) {
        return 2;
    }

    int offset = 0;

    unsigned char protocol_version = payload[offset++];
    char* server_version = (char*) &payload[offset];
    offset += strlen(server_version) + 1;

    uint32_t connection_id =
            (unsigned char)payload[offset] +
            (unsigned char)payload[offset + 1] * 256 +
            (unsigned char)payload[offset + 2] * 65536 +
            (unsigned char)payload[offset + 3] * 16777216;

    offset += 4;

    unsigned char auth_plugin_data_part_one[8];
    memcpy(auth_plugin_data_part_one, &payload[offset], 8);

    offset += 8;
    offset += 1;

    uint16_t cpb_flags_lower = payload[offset] | (payload[offset + 1] * 256);
    offset += 2;

    unsigned char character_set = payload[offset++];
    uint16_t status_flag = payload[offset] | (payload[offset + 1] * 256);
    offset += 2;

    uint16_t cpb_flags_upper = payload[offset] | (payload[offset + 1] * 256);
    offset += 2;

    uint32_t cpb_flags = cpb_flags_lower | (cpb_flags_upper * 65536);

    unsigned char auth_plugin_data_len = 0;
    if (cpb_flags & (1 << 21)) {
        auth_plugin_data_len = payload[offset++];
    } else {
        offset++;
    }

    offset += 10;

    unsigned char auth_plugin_data_part_two[256];
    int part_two_len = ((auth_plugin_data_len > 8 + 1) ? (auth_plugin_data_len - 8) : 0);
    if (part_two_len > 0) {
        memcpy(auth_plugin_data_part_two, &payload[offset], part_two_len);
        offset += part_two_len;
    }

    char* auth_plugin_name = (char*) &payload[offset];

    data->seq_id = seq_id;
    data->protocol_version = protocol_version;
    data->server_version = strdup(server_version);
    data->connection_id = connection_id;

    memcpy(data->auth_plugin_data_part_one, auth_plugin_data_part_one, 8);
    memcpy(data->auth_plugin_data_part_two, auth_plugin_data_part_two, part_two_len);
    data->auth_plugin_name = strdup(auth_plugin_name);

    data->cpb_flags_lower = cpb_flags_lower;
    data->cpb_flags_upper = cpb_flags_upper;
    data->cpb_flags = cpb_flags;
    data->status_flag = status_flag;

    data->character_set = character_set;

    free(payload);
    return 0;
}

int mysql_driver_reply_client_handshake_response_packet(
        SOCKET socket,
        mysql_server_handshake_data data,
        mysql_connection_data connection_data
) {
    uint32_t max_packet_size = 0x01000000;
    unsigned char character_set = data.character_set;
    char* username = connection_data.username;
    char* password = connection_data.password;
    char* database = connection_data.database;
    char* plugin_name = data.auth_plugin_name;

    unsigned char auth_response[20] = {0};
    int auth_response_len = 0;

    if (password == NULL || password[0] == '\0') {
        auth_response_len = 1;
        auth_response[0] = 0x00;
    } else {
        unsigned char stage1[32], stage2[32], stage3[32];
        unsigned char seed[32];
        memcpy(seed, data.auth_plugin_data_part_one, 8);
        memcpy(seed + 8, data.auth_plugin_data_part_two, 12);

        int seed_len = 20;

        sha256(password, strlen(password), stage1);
        sha256(stage1, 32, stage2);

        unsigned char combined[32 + seed_len];
        memcpy(combined, seed, seed_len);
        memcpy(combined + seed_len, stage2, 32);

        sha256(combined, seed_len + 32, stage3);

        for (int i = 0; i < 32; ++i) {
            auth_response[i] = stage3[i] ^ stage1[i];
        }
        auth_response_len = 32;
    }

    uint32_t capability_flags =
            CLIENT_LONG_PASSWORD |
            CLIENT_CONNECT_WITH_DB |
            CLIENT_PROTOCOL_41 |
            CLIENT_SECURE_CONNECTION |
            CLIENT_PLUGIN_AUTH |
            CLIENT_FOUND_ROWS |
            CLIENT_LONG_FLAG;

    unsigned char payload[1024];
    int offset = 0;

    payload[offset++] = capability_flags & 0xFF;
    payload[offset++] = (capability_flags >> 8) & 0xFF;
    payload[offset++] = (capability_flags >> 16) & 0xFF;
    payload[offset++] = (capability_flags >> 24) & 0xFF;

    payload[offset++] = max_packet_size & 0xFF;
    payload[offset++] = (max_packet_size >> 8) & 0xFF;
    payload[offset++] = (max_packet_size >> 16) & 0xFF;
    payload[offset++] = (max_packet_size >> 24) & 0xFF;

    payload[offset++] = character_set;

    memset(payload + offset, 0, 23);
    offset += 23;

    strcpy((char*)(payload + offset), username);
    offset += strlen(username) + 1;

    payload[offset++] = (unsigned char)auth_response_len;

    memcpy(payload + offset, auth_response, auth_response_len);
    offset += auth_response_len;

    if (database && database[0]) {
        strcpy((char*)(payload + offset), database);
        offset += strlen(database) + 1;
    }

    if (plugin_name && plugin_name[0]) {
        strcpy((char*)(payload + offset), plugin_name);
        offset += strlen(plugin_name) + 1;
    }

    unsigned char packet[1024 + 4];
    int payload_len = offset;
    packet[0] = payload_len & 0xFF;
    packet[1] = (payload_len >> 8) & 0xFF;
    packet[2] = (payload_len >> 16) & 0xFF;
    packet[3] = 1;

    memcpy(packet + 4, payload, payload_len);

    int res = tcp_send_packet(socket, 1, payload, payload_len);
    if (res != 0) {
        return 200 + res;
    }

    unsigned char ok_header[4];
    int recv_len = recv(socket, (char*)ok_header, 4, 0);
    if (recv_len != 4) {
        return 300;
    }

    int server_payload_len = ok_header[0] + (ok_header[1] << 8) + (ok_header[2] << 16);

    unsigned char* server_payload = malloc(server_payload_len);
    if (!server_payload) {
        return 301;
    }

    int total_recv = 0;
    while (total_recv < server_payload_len) {
        int rec = recv(socket, (char*)server_payload + total_recv, server_payload_len - total_recv, 0);
        if (rec <= 0) {
            free(server_payload);
            return 302;
        }
        total_recv += rec;
    }

    int code;
    if (server_payload[0] == 0x00) {
        code = 0;
    } else if (server_payload[0] == 0xFF) {
        unsigned short error_code = server_payload[1] | (server_payload[2] << 8);
        code = 1000 + error_code;
    } else {
        code = 303;
    }

    free(server_payload);
    return code;
}

void mysql_driver_free_handshake(mysql_server_handshake_data* data) {
    if (data->server_version) free(data->server_version);
    if (data->auth_plugin_name) free(data->auth_plugin_name);
}

int mysql_driver_net_handshake(mysql_connection_data connection_data, SOCKET* out_socket) {
    SOCKET sock;
    int res = tcp_connect(connection_data.host, connection_data.port, &sock);

    if (res != 0) return res;

    mysql_server_handshake_data data = {0};

    res = mysql_driver_read_handshake(sock, &data);
    if (res != 0) {
        mysql_driver_free_handshake(&data);
        WSACleanup();
        res += 4;
        return res;
    }

    res = mysql_driver_reply_client_handshake_response_packet(sock, data, connection_data);
    if (res != 0) {
        mysql_driver_free_handshake(&data);
        WSACleanup();
        if (res >= 1000 || res < 0) return res;
        res += 7;
        return res;
    }

    WSACleanup();

    *out_socket = sock;
    return 0;
}