#ifndef MYSQL_DRIVER_STRUCTURES_H
#define MYSQL_DRIVER_STRUCTURES_H

#include <stdbool.h>
#include <stdint.h>
#include <winsock2.h>

typedef struct {
    char* host;
    int port;
    char* username;
    char* password;
    char* database;
} mysql_connection_data;

typedef struct {
    bool status;
    char* message;
    SOCKET sock;
} mysql_connection_t;

typedef struct {
    int seq_id;
    unsigned char protocol_version;
    char* server_version;
    uint32_t connection_id;

    unsigned char auth_plugin_data_part_one[8];
    unsigned char auth_plugin_data_part_two[256];
    char* auth_plugin_name;

    uint16_t cpb_flags_lower;
    uint16_t cpb_flags_upper;
    uint32_t cpb_flags;
    uint16_t status_flag;

    unsigned char character_set;
} mysql_server_handshake_data;

#endif //MYSQL_DRIVER_STRUCTURES_H
