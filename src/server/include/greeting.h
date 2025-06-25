#ifndef GREETING_H
#define GREETING_H

#define NO_AUTH 0x00
#define USER_PASS 0x02
#define NO_ACCEPTABLE_METHODS 0xFF

#include <stdint.h>
#include <stdlib.h>
#include "../../utils/include/buffer.h"

typedef struct {
    uint8_t version;          
    uint8_t nmethods;         
    uint8_t methods[255]; //mn
} socks5_greeting_req;

typedef struct {
    uint8_t version; 
    uint8_t method;          
} socks5_greeting_rep;

typedef struct {
    socks5_greeting_req req; 
    socks5_greeting_rep rep; 
    size_t bytes_read;   
    size_t bytes_written;
} socks5_greeting;

#endif 
