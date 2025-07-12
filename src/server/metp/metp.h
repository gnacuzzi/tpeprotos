#ifndef METP_H
#define METP_H

#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "metrics.h"
#include "users.h"
#include "../../utils/include/stm.h"
#include "../../utils/include/buffer.h"
#include "../../utils/include/selector.h"

#define BUFFER_SIZE 1024
#define MAX_BUFFER_SIZE 2048
#define METP_VERSION  "METP/1.0"

typedef enum {
    METP_HELLO,
    METP_HELLO_REPLY,
    METP_AUTH,
    METP_AUTH_REPLY,
    METP_REQUEST,
    METP_REQUEST_REPLY,
    METP_ERROR,
    METP_DONE         
} metp_state;

typedef struct {
    int sockfd;            
    bool is_connected;     
    bool is_authenticated;
    bool must_close;
    char authenticated_user[MAX_USERNAME_LEN];
    
    uint8_t *raw_read_buffer;
    uint8_t *raw_write_buffer;
    size_t buffer_size;
    buffer read_buffer;
    buffer write_buffer;

    const char *send_ptr;
    size_t send_remaining;
    bool sending_data;

    union {
        struct {
            char   line[BUFFER_SIZE];
            size_t idx;
        } auth;
        struct {
            char   line[BUFFER_SIZE];
            size_t idx;
        } request;
    } parsers;

    struct state_machine stm;

    bool stm_is_valid;

} metp_session;

const struct state_definition *get_metp_states(void);

bool set_io_buffer_size(size_t size);
size_t get_io_buffer_size(void);
bool resize_metp_buffers(metp_session *s, size_t new_size);

#endif
