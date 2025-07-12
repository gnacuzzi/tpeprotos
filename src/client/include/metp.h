#ifndef METP_H
#define METP_H

#include <stdbool.h>
#include <stdint.h>
#include <memory.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

typedef struct {
    char *name;
    char *pass;
} proxy_user;

typedef enum {
    PC_SUCCESS = 0,
    PC_SERV_FAIL,
    PC_AUTH_FAIL,
} pc_connect_status;

typedef enum {
    PC_RES_SUCCESS = 0,
    PC_RES_SERV_FAIL,
    PC_RES_CMD_FAIL,
    PC_RES_NOT_AUTHORIZED,
} pc_response_status;

typedef struct {
    char *command;
    char *key;
    char *value;
} proxy_command;

typedef struct {
    uint64_t historical_connections;
    uint64_t current_connections;
    uint64_t bytes_transferred;
} proxy_metrics;

typedef struct {
    char *timestamp;
    char *user;
    char *ip_src;
    char *dest;
    uint64_t bytes;
} proxy_log_entry;

typedef struct {
    uint8_t count;
    proxy_log_entry *entries;
} proxy_log_list;

typedef struct {
    char *username;
    char *role;
} proxy_user_entry;

typedef struct {
    uint8_t count;
    proxy_user_entry *entries;
} proxy_user_list;

pc_connect_status proxy_connect(const char *host, unsigned short port, const proxy_user *user);
void proxy_close(void);
pc_response_status proxy_quit(void);

pc_response_status proxy_get_metrics(proxy_metrics *m);
pc_response_status proxy_get_logs (proxy_log_list *L);
pc_response_status proxy_get_users(proxy_user_list *U);

pc_response_status proxy_set_max_io_buffer (uint64_t bytes);
pc_response_status proxy_add_user (const proxy_user *u);
pc_response_status proxy_remove_user (const char *username);
pc_response_status proxy_set_role (const char *username, const char *role);

void free_proxy_log_list(proxy_log_list *L);
void free_proxy_user_list(proxy_user_list *U);

const char* pc_connect_status_to_string(pc_connect_status status);

const char* pc_response_status_to_string(pc_response_status status);

#endif
