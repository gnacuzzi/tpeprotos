#include "include/authentication.h"

void authentication_init(socks5_authentication * parser) {
    parser->req.ver = 0;
    parser->req.ulen = 0;
    parser->req.plen = 0;
    parser->bytes_read = 0;
    parser->bytes_written = 0;
    parser->idx = AUTHENTICATION_VER;
    parser->rep.ver = AUTHENTICATION_VERSION;
    parser->rep.status = AUTHENTICATION_STATUS_SUCCESS;
}

authentication_idx authentication_parse(socks5_authentication * parser, buffer *buff, bool *error) {
    while (buffer_can_read(buff)) {
        uint8_t b = buffer_read(buff);
        switch (parser->idx) {
        case AUTHENTICATION_VER:
            parser->req.ver = b;
            if (b != AUTHENTICATION_VERSION) {
                parser->idx = AUTHENTICATION_ERROR_VERSION;
                parser->rep.status = AUTHENTICATION_STATUS_FAILED;
                *error = true;
                return parser->idx;
            }
            parser->idx = AUTHENTICATION_ULEN;
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
                parser->bytes_read = 0;
                parser->idx = AUTHENTICATION_PLEN;
            }
            break;

        case AUTHENTICATION_PLEN:
            parser->req.plen = b;
            parser->bytes_read = 0;
            if (b == 0) {
                parser->req.cred.passwd[0] = '\0';
                parser->idx = AUTHENTICATION_DONE;
                return parser->idx;
            }
            parser->idx = AUTHENTICATION_PASSWD;
            break;

        case AUTHENTICATION_PASSWD:
            parser->req.cred.passwd[parser->bytes_read++] = b;
            if (parser->bytes_read == parser->req.plen) {
                parser->req.cred.passwd[parser->bytes_read] = '\0';
                parser->idx = AUTHENTICATION_DONE;
                return parser->idx;
            }
            break;

        case AUTHENTICATION_DONE:
        case AUTHENTICATION_ERROR_VERSION:
        case AUTHENTICATION_ERROR_OTHER:
            return parser->idx;

        default:
            parser->idx = AUTHENTICATION_ERROR_OTHER;
            parser->rep.status = AUTHENTICATION_STATUS_FAILED;
            *error = true;
            return parser->idx;
        }
    }
    return parser->idx;
}
