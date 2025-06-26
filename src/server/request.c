#include "include/socks5.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

int socks5_parse_request(const uint8_t *buf, size_t len, socks5_request *req, size_t *consumed){
    size_t pos = 0;

    if (len < 4) {
        return -1;
    }

    req->version = buf[pos++];
    if (req->version != SOCKS5_VERSION) {
        return -1;
    }

    req->cmd = buf[pos++];
    req->rsv = buf[pos++];
    if (req->rsv != 0x00) {
        return -1;
    }

    req->dst.atyp = buf[pos++];
    switch (req->dst.atyp) {
        case SOCKS5_ATYP_IPV4:
            if (len < pos + 4 + 2) {
                return -1;
            }
            memcpy(req->dst.addr.ipv4, buf + pos, 4);
            pos += 4;
            {
                uint16_t netport;
                memcpy(&netport, buf + pos, 2);
                req->dst.port = ntohs(netport);
            }
            pos += 2;
            break;

        case SOCKS5_ATYP_DOMAIN:
            {
                if (len < pos + 1) {
                    return -1;
                }
                uint8_t dlen = buf[pos++];
                if (len < pos + dlen + 2) {
                    return -1;
                }
                req->dst.addr.domain.len = dlen;
                req->dst.addr.domain.name = malloc(dlen + 1);
                if (!req->dst.addr.domain.name) {
                    return -1;
                }
                memcpy(req->dst.addr.domain.name, buf + pos, dlen);
                req->dst.addr.domain.name[dlen] = '\0';
                pos += dlen;
                {
                    uint16_t netport;
                    memcpy(&netport, buf + pos, 2);
                    req->dst.port = ntohs(netport);
                }
                pos += 2;
            }
            break;

        case SOCKS5_ATYP_IPV6:
            if (len < pos + 16 + 2) {
                return -1;
            }
            memcpy(req->dst.addr.ipv6, buf + pos, 16);
            pos += 16;
            {
                uint16_t netport;
                memcpy(&netport, buf + pos, 2);
                req->dst.port = ntohs(netport);
            }
            pos += 2;
            break;

        default:
            return -1;
    }

    *consumed = pos;
    return 0;
}

void socks5_request_free(socks5_request *req) {
    if (req->dst.atyp == SOCKS5_ATYP_DOMAIN) {
        free(req->dst.addr.domain.name);
        req->dst.addr.domain.name = NULL;
    }
}

int socks5_build_reply(const socks5_reply *r, uint8_t **out_buf, size_t *out_len) {
    size_t addr_len;
    switch (r->bnd.atyp) {
        case SOCKS5_ATYP_IPV4:    addr_len = 4;   break;
        case SOCKS5_ATYP_DOMAIN:  addr_len = 1 + r->bnd.addr.domain.len; break;
        case SOCKS5_ATYP_IPV6:    addr_len = 16;  break;
        default:
            return -1;
    }

    size_t total = 4 + addr_len + 2;
    uint8_t *buf = malloc(total);
    if (!buf) {
        return -1;
    }

    size_t pos = 0;
    buf[pos++] = r->version;
    buf[pos++] = r->rep;
    buf[pos++] = 0x00;             
    buf[pos++] = r->bnd.atyp;

    switch (r->bnd.atyp) {
        case SOCKS5_ATYP_IPV4:
            memcpy(buf + pos, r->bnd.addr.ipv4, 4);
            pos += 4;
            break;
        case SOCKS5_ATYP_DOMAIN:
            buf[pos++] = r->bnd.addr.domain.len;
            memcpy(buf + pos,
                   r->bnd.addr.domain.name,
                   r->bnd.addr.domain.len);
            pos += r->bnd.addr.domain.len;
            break;
        case SOCKS5_ATYP_IPV6:
            memcpy(buf + pos, r->bnd.addr.ipv6, 16);
            pos += 16;
            break;
    }

    {
        uint16_t netport = htons(r->bnd.port);
        memcpy(buf + pos, &netport, 2);
    }
    *out_buf = buf;
    *out_len = total;
    return 0;
}
