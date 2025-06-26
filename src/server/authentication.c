#include "include/authentication.h"

void authentication_init(socks5_authentication * parser) {
    parser->req.ver = 0x01; 
    parser->req.ulen = 0;   
    parser->req.plen = 0;   
    parser->bytes_read = 0;
    parser->bytes_written = 0;
    parser->idx = AUTHENTICATION_VER;
    parser->rep.ver = 0x01; 
    parser->rep.status = AUTHENTICATION_STATUS_SUCCESS;
}

authentication_idx authentication_parse(socks5_authentication * parser, buffer *buff, bool *error) {
    while (buffer_can_read(buff)) {
        uint8_t b = buffer_read(buff);
        switch (parser->idx) {
        case AUTHENTICATION_VER:
            parser->req.ver = b;
            if (b != 0x01) {
                parser->rep.status = AUTHENTICATION_STATUS_FAILED;
                *error = true;
                return parser->idx;
            }
            parser->idx = AUTHENTICATION_ULEN;
            parser->bytes_read = 0;
            break;

        case AUTHENTICATION_ULEN:
            parser->req.ulen = b;
            parser->bytes_read = 0;
            if (b == 0) {
                parser->idx = AUTHENTICATION_PLEN;
            } else {
                parser->idx = AUTHENTICATION_UNAME;
            }
            break;

        case AUTHENTICATION_UNAME:
            parser->req.cred.usernme[parser->bytes_read++] = b;
            if (parser->bytes_read == parser->req.ulen) {
                parser->req.cred.usernme[parser->bytes_read] = '\0';
                parser->idx = AUTHENTICATION_PLEN;
                parser->bytes_read = 0;
            }
            break;

        case AUTHENTICATION_PLEN:
            parser->req.plen = b;
            parser->bytes_read = 0;
            parser->idx = AUTHENTICATION_PASSWD;
            if (b == 0) {
                // no hay contraseña
                parser->req.cred.passwd[0] = '\0';
                return parser->idx;
            }
            break;

        case AUTHENTICATION_PASSWD:
            parser->req.cred.passwd[parser->bytes_read++] = b;
            if (parser->bytes_read == parser->req.plen) {
                parser->req.cred.passwd[parser->bytes_read] = '\0';
                return parser->idx;
            }
            break;
        }
    }
    return parser->idx;
}

