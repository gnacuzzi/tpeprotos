#ifndef ARGSMETP_H_
#define ARGSMETP_H_

#include <stdbool.h>
#include <stdint.h>

#define MAX_NAME   64
#define MAX_PASS   64
#define MAX_ROLE   64
#define MAX_USERS  16

typedef struct {
    char name[MAX_NAME];
    char pass[MAX_PASS];
} metp_user;

enum metp_mode {
    MODE_NONE,
    MODE_GET_LOGS,
    MODE_GET_METRICS,
    MODE_CHANGE_BUFFER,
    MODE_ADD_USER,
    MODE_DELETE_USER,
    MODE_SET_ROLE
};

typedef struct {
    char            *metp_addr;
    unsigned short   metp_port;

    char             auth_user[MAX_NAME];
    char             auth_pass[MAX_PASS];

    metp_user        users[MAX_USERS];
    int              nusers;

    char             du_user[MAX_NAME];

    char             sr_user[MAX_NAME];
    char             sr_role[MAX_ROLE];

    uint64_t         cb_size;

    enum metp_mode   mode;
} metpargs;

void parsemetp_args(int argc, char **argv, metpargs *args);

#endif 
