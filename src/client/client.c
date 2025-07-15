#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "include/argsmetp.h"  
#include "include/metp.h"       

int main(int argc, char **argv) {
    metpargs args;
    parsemetp_args(argc, argv, &args);

    proxy_user auth = {
        .name = args.auth_user,
        .pass = args.auth_pass
    };
    fprintf(stderr, "Conecting a %s:%u with user '%s'\n",
            args.metp_addr, args.metp_port, auth.name);
    fflush(stderr);
    pc_connect_status cst = proxy_connect(
        args.metp_addr,
        args.metp_port,
        &auth
    );
    if (cst != PC_SUCCESS) {
        fprintf(stderr, "%s\n",
                pc_connect_status_to_string(cst));
        return 1;
    }

    pc_response_status rst;
    switch (args.mode) {

    case MODE_GET_LOGS: {
        proxy_log_list logs;
        rst = proxy_get_logs(&logs);
        if (rst == PC_RES_SUCCESS) {
            for (uint8_t i = 0; i < logs.count; i++) {
                proxy_log_entry *e = &logs.entries[i];
                printf("[%s] %s %s %s %" PRIu64 "\n",
                       e->timestamp,
                       e->user,
                       e->ip_src,
                       e->dest,
                       e->bytes);
            }
            free_proxy_log_list(&logs);
        } else {
            fprintf(stderr, "%s\n",
                    pc_response_status_to_string(rst));
        }
        break;
    }

    case MODE_GET_METRICS: {
        proxy_metrics m;
        rst = proxy_get_metrics(&m);
        if (rst == PC_RES_SUCCESS) {
            printf("Historical Connections: %" PRIu64 "\n"
                   "Current Connections:    %" PRIu64 "\n"
                   "Bytes Transferred:      %" PRIu64 "\n",
                   m.historical_connections,
                   m.current_connections,
                   m.bytes_transferred);
        } else {
            fprintf(stderr, "%s\n",
                    pc_response_status_to_string(rst));
        }
        break;
    }

    case MODE_USERS: {
        proxy_user_list users;
        rst = proxy_get_users(&users);
        if (rst == PC_RES_SUCCESS) {
            for (uint8_t i = 0; i < users.count; i++) {
                proxy_user_entry *e = &users.entries[i];
                printf("%s %s\n", e->username, e->role);
            }
            free_proxy_user_list(&users);
        } else {
            fprintf(stderr, "%s\n",
                    pc_response_status_to_string(rst));
        }
        break;
    }
    case MODE_CHANGE_BUFFER:
        rst = proxy_set_max_io_buffer(args.cb_size);
        printf("%s\n", pc_response_status_to_string(rst));
        break;

    case MODE_ADD_USER: {
        for (int i = 0; i < args.nusers; i++) {
            metp_user *u = &args.users[i];
            rst = proxy_add_user((proxy_user[]){
                { .name = u->name, .pass = u->pass }
            });
            printf("%s\n", pc_response_status_to_string(rst));
        }
        break;
    }

    case MODE_DELETE_USER:
        rst = proxy_remove_user(args.du_user);
        printf("%s\n", pc_response_status_to_string(rst));
        break;

    case MODE_SET_ROLE:
        rst = proxy_set_role(args.sr_user, args.sr_role);
        printf("%s\n", pc_response_status_to_string(rst));
        break;

    default:
        fprintf(stderr, "Invalid mode\n");
        break;
    }

    proxy_quit();
    proxy_close();
    return 0;
}
