#ifndef REQUEST_H
#define REQUEST_H

#include <stdint.h>
#include <stdlib.h>

#define SOCKS5_VERSION 0x05

typedef enum {
    SOCKS5_CMD_CONNECT       = 0x01,
    SOCKS5_CMD_BIND          = 0x02,
    SOCKS5_CMD_UDP_ASSOCIATE = 0x03
} socks5_command;

typedef enum {
    SOCKS5_ATYP_IPV4    = 0x01,
    SOCKS5_ATYP_DOMAIN  = 0x03,
    SOCKS5_ATYP_IPV6    = 0x04
} socks5_atyp;

typedef enum {
    SOCKS5_REP_SUCCEEDED              = 0x00,
    SOCKS5_REP_GENERAL_FAILURE        = 0x01,
    SOCKS5_REP_CONN_NOT_ALLOWED       = 0x02,
    SOCKS5_REP_NETWORK_UNREACHABLE    = 0x03,
    SOCKS5_REP_HOST_UNREACHABLE       = 0x04,
    SOCKS5_REP_CONNECTION_REFUSED     = 0x05,
    SOCKS5_REP_TTL_EXPIRED            = 0x06,
    SOCKS5_REP_COMMAND_NOT_SUPPORTED  = 0x07,
    SOCKS5_REP_ATYP_NOT_SUPPORTED     = 0x08
} socks5_reply_code;

typedef struct {
    socks5_atyp  atyp;
    union {
        uint8_t  ipv4[4];
        struct {
            uint8_t len;    
            char   *name;  
        } domain;
        uint8_t  ipv6[16];
    } addr;
    uint16_t port;
} socks5_address;

typedef struct {
    uint8_t           version;
    socks5_command    cmd;
    uint8_t           rsv;     
    socks5_address    dst;
} socks5_request;

typedef struct {
    uint8_t            version;
    socks5_reply_code rep;
    uint8_t             rsv;    
    socks5_address    bnd;
} socks5_reply;

typedef struct{
    socks5_request request;        
    socks5_reply   reply;       
} socks5_request_parser;

int socks5_parse_request(const uint8_t *buf, size_t len, socks5_request *req, size_t *consumed);

void socks5_request_free(socks5_request *req);

int socks5_build_reply(const socks5_reply *r, uint8_t **out_buf, size_t *out_len);

#endif 
