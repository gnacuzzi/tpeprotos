#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <pthread.h>

#include <netinet/in.h>   
#include "greeting.h"
#include "request.h"
#include "../../utils/include/buffer.h"
#include "../../utils/include/selector.h"
#include "../../utils/include/stm.h"    
#include "authentication.h"    
#include "../../utils/include/args.h" 
#include "../metp/metrics.h"

#define BUF_SIZE 4096

typedef enum {
    SOCKS5_GREETING,         
    SOCKS5_GREETING_REPLY,   
    SOCKS5_METHOD,
    SOCKS5_METHOD_REPLY,
    SOCKS5_REQUEST,          
    SOCKS5_REQUEST_REPLY,   
    SOCKS5_REQUEST_CONNECT,
    SOCKS5_REQUEST_BIND, 
    SOCKS5_STREAM, 
    SOCKS5_ERROR,          
    SOCKS5_CLOSING,
    SOCKS5_REQUEST_RESOLV           
} socks5_state;

typedef struct {
    int client_fd;           
    int remote_fd;           
    socks5_state state;

    char source_ip[64];
    char dest_str[256];
    uint64_t bytes_transferred;

    buffer c2p_read, c2p_write;
    uint8_t raw_c2p_r[BUF_SIZE], raw_c2p_w[BUF_SIZE];

    buffer p2c_read, p2c_write;
    uint8_t raw_p2c_r[BUF_SIZE], raw_p2c_w[BUF_SIZE];

    union {
        socks5_greeting greeting;
        socks5_request_parser request; 
        socks5_authentication  authentication;
    } parsers;

    struct state_machine stm;
    bool is_closing;

    struct user * user;
    uint8_t auth_status;
    int log_id;

    struct addrinfo *resolved_addr;         
    struct addrinfo *resolved_addr_current; 

    int                remote_domain;     
    socklen_t          remote_addr_len;    
    struct sockaddr_storage remote_addr;   
} socks5_session;

const struct state_definition *get_socks5_states(void);


#endif
