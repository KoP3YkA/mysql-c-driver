#include <stdio.h>
#include "include/structures.h"
#include "include/mysql.h"

int main() {
    mysql_connection_data data = {
            "127.0.0.1",
            3306,
            "root",
            "1",
            "orm"
    };
    mysql_connection_t res = mysql_driver_connect(data);
    printf("%d\n", res.status);
    printf("%s\n", res.message);
    return 0;
}
