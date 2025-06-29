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
#include "../../utils/include/stm.h"
#include "../../utils/include/buffer.h"
#include "../../utils/include/selector.h"

#define BUFFER_SIZE 1024
#define METP_VERSION  "METP/1.0"

typedef enum {
    METP_HELLO,
    METP_HELLO_REPLY,
    METP_AUTH,
    METP_AUTH_REPLY,
    METP_REQUEST,
    METP_REQUEST_REPLY,
    METP_DONE,
    METP_ERROR          
} metp_state;

typedef struct {
    int sockfd;            
    bool is_connected;     
    bool is_authenticated; 
    
    uint8_t raw_read_buffer[BUFFER_SIZE];
    uint8_t raw_write_buffer[BUFFER_SIZE];
    buffer read_buffer;
    buffer write_buffer;

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
} metp_session;

const struct state_definition *get_metp_states(void);

#endif
