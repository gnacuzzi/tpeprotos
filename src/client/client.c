#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "include/metp.h"

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 8080

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [HOST] [PORT] [USER] [PASSWORD] [OPTION]...\n"
        "\n [HOST] and [PORT] may be specified as '-' to use defaults.\n"
        "\n   -h                                      Prints help and finish.\n"
        "   GET_LOGS                                Gets proxy logs.\n"
        "   GET_METRICS                              Gets proxy statistics.\n"
        "   CHANGE-BUFFER <size>                   Changes the buffer size.\n"
        "   ADD-USER <username> <password>         Adds a user.\n"
        "   DELETE-USER <username>                 Deletes a user.\n"
        "   SET-ROLE <username> <role>             Changes a user's role.\n"
        "\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc <= 5 || (argc > 5 && strcmp("-h", argv[5]) == 0)) {
        print_usage(argv[0]);
        return 0;
    }

    const char *host = (strcmp(argv[1], "-") != 0) ? argv[1] : DEFAULT_HOST;
    unsigned short port = (unsigned short)(strcmp(argv[2], "-") != 0 ? atoi(argv[2]) : DEFAULT_PORT);

    proxy_user user = { .name = argv[3], .pass = argv[4] };

    pc_connect_status cst = proxy_connect(host, port, &user);
    if (cst != PC_SUCCESS) {
        fprintf(stderr, "%s\n", pc_connect_status_to_string(cst));
        return 1;
    }

    const char *cmd = argv[5];
    pc_response_status rst;

    if (strcmp(cmd, "GET-LOGS") == 0) {
        proxy_log_list logs;
        rst = proxy_get_logs(&logs);
        if (rst == PC_RES_SUCCESS) {
            for (uint8_t i = 0; i < logs.count; i++) {
                proxy_log_entry *e = &logs.entries[i];
                printf("[%s] %s %s %s %" PRIu64 "\n",
                       e->timestamp, e->user, e->ip_src, e->dest, e->bytes);
            }
            free_proxy_log_list(&logs);
        } else {
            fprintf(stderr, "%s\n", pc_response_status_to_string(rst));
        }
    }
    else if (strcmp(cmd, "GET-METRICS") == 0) {
        proxy_metrics m;
        rst = proxy_get_metrics(&m);
        if (rst == PC_RES_SUCCESS) {
            printf("Historical Connections: %" PRIu64 "\nCurrent Connections: %" PRIu64 "\nBytes Transferred: %" PRIu64 "\n",
                   m.historical_connections,
                   m.current_connections,
                   m.bytes_transferred);
        } else {
            fprintf(stderr, "%s\n", pc_response_status_to_string(rst));
        }
    }
    else if (strcmp(cmd, "CHANGE-BUFFER") == 0) {
        if (argc != 7) {
            print_usage(argv[0]);
            proxy_close();
            return 1;
        }
        uint64_t size = strtoull(argv[6], NULL, 10);
        rst = proxy_set_max_io_buffer(size);
        printf("%s\n", pc_response_status_to_string(rst));
    }
    else if (strcmp(cmd, "ADD-USER") == 0) {
        if (argc != 8) {
            print_usage(argv[0]);
            proxy_close();
            return 1;
        }
        proxy_user nu = { .name = argv[6], .pass = argv[7] };
        rst = proxy_add_user(&nu);
        printf("%s\n", pc_response_status_to_string(rst));
    }
    else if (strcmp(cmd, "DELETE-USER") == 0) {
        if (argc != 7) {
            print_usage(argv[0]);
            proxy_close();
            return 1;
        }
        rst = proxy_remove_user(argv[6]);
        printf("%s\n", pc_response_status_to_string(rst));
    }
    else if (strcmp(cmd, "SET-ROLE") == 0) {
        if (argc != 8) {
            print_usage(argv[0]);
            proxy_close();
            return 1;
        }
        rst = proxy_set_role(argv[6], argv[7]);
        printf("%s\n", pc_response_status_to_string(rst));
    }
    else {
        fprintf(stderr, "Unknown option '%s'\n", cmd);
        print_usage(argv[0]);
    }

    proxy_close();
    return 0;
}
