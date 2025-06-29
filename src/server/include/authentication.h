#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include "../../utils/include/buffer.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static const uint8_t AUTHENTICATION_STATUS_SUCCESS = 0x00;
static const uint8_t AUTHENTICATION_STATUS_FAILED = 0x01;

 typedef enum authentication_idx {
    AUTHENTICATION_VER,
    AUTHENTICATION_ULEN,
    AUTHENTICATION_UNAME,
    AUTHENTICATION_PLEN,
    AUTHENTICATION_PASSWD,
    AUTHENTICATION_DONE,           
    AUTHENTICATION_ERROR_VERSION,  
    AUTHENTICATION_ERROR_OTHER
 }authentication_idx;

 typedef struct{
    char usernme[256];
    char passwd[256];
 } credentials;

 typedef struct{
    uint8_t ver;
    uint8_t ulen;
    uint8_t plen;
    credentials cred;
 } socks5_authentication_req;

typedef struct {
    uint8_t ver;
    uint8_t status;
} socks5_authentication_rep;

typedef struct {
    socks5_authentication_req req;
    socks5_authentication_rep rep;
    size_t bytes_read;
    size_t bytes_written;
    authentication_idx idx;
} socks5_authentication;


authentication_idx authentication_parse(socks5_authentication * parser, buffer *buff, bool *error);
void authentication_init(socks5_authentication * parser);

#endif