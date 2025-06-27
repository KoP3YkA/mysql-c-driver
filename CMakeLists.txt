cmake_minimum_required(VERSION 3.27)
project(mysql_driver C)

set(CMAKE_C_STANDARD 11)


add_executable(mysql_driver main.c
        src/mysql.c
        include/mysql.h
        include/structures.h
        src/handshake_manager.c
        include/handshake_manager.h
        libs/sha256.c
        libs/sha256.h
        src/tcp_manager.c
        include/tcp_manager.h)

target_link_libraries(mysql_driver ws2_32)
