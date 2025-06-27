#include "include/socks5.h"

static void on_greet(const unsigned state, struct selector_key *key);
static unsigned on_greet_read   (struct selector_key *key);
static unsigned on_greet_write  (struct selector_key *key);
static void on_authentication(const unsigned state, struct selector_key *key);
static unsigned on_authentication_read(struct selector_key *key);
static unsigned on_authentication_write(struct selector_key *key);

static void on_request(const unsigned state, struct selector_key *key);
static unsigned on_request_read (struct selector_key *key);
static unsigned on_request_forward_read(struct selector_key *key);
static unsigned on_request_forward_write(struct selector_key *key);
static unsigned on_request_connect_write(struct selector_key *key);
static unsigned on_request_bind_write(struct selector_key *key);

static const struct state_definition socks5_states[] = {
    [SOCKS5_GREETING] = {
        .state          = SOCKS5_GREETING,
        .on_arrival     = on_greet,
        .on_read_ready  = on_greet_read,
    },
    [SOCKS5_GREETING_REPLY] = {
        .state          = SOCKS5_GREETING_REPLY,
        .on_write_ready = on_greet_write,
    },
    [SOCKS5_METHOD] = {
        .state          = SOCKS5_METHOD,
        .on_arrival     = on_authentication,
        .on_read_ready  = on_authentication_read,
    },
    [SOCKS5_METHOD_REPLY] = {
        .state          = SOCKS5_METHOD_REPLY,
        .on_write_ready = on_authentication_write,
    },
    [SOCKS5_REQUEST] = {
        .state          = SOCKS5_REQUEST,
        .on_arrival     = on_request,
        .on_read_ready  = on_request_read,
    },
    [SOCKS5_REQUEST_REPLY] = {
        .state          = SOCKS5_REQUEST_REPLY,
        .on_read_ready  = on_request_forward_read,
        .on_write_ready = on_request_forward_write,
    },
    [SOCKS5_REQUEST_CONNECT] = {
        .state          = SOCKS5_REQUEST_CONNECT,   
        .on_write_ready = on_request_connect_write,
    },
    [SOCKS5_REQUEST_BIND] = {
        .state          = SOCKS5_REQUEST_BIND,
        .on_write_ready  = on_request_bind_write,
    },
    [SOCKS5_STREAM] = {
        .state          = SOCKS5_STREAM,
        .on_read_ready  = on_request_forward_read,
        .on_write_ready = on_request_forward_write,
    },
    [SOCKS5_ERROR] = {
        .state          = SOCKS5_ERROR,
    },
    [SOCKS5_CLOSING] = {
        .state          = SOCKS5_CLOSING,
    },
};

const struct state_definition *get_socks5_states(void) {
  return socks5_states;
}


//GREETING
static void on_greet(const unsigned state, struct selector_key *key) {
    socks5_session *s = key->data;
    s->parsers.greeting.req.version = 0x05; 
    s->parsers.greeting.req.nmethods = 0; 
    s->parsers.greeting.bytes_read = 0;
    s->parsers.greeting.bytes_written = 0;

    s->parsers.greeting.rep.version = 0x05; 
    s->parsers.greeting.rep.method = NO_ACCEPTABLE_METHODS; 
}

static unsigned on_greet_read(struct selector_key *key) {
    socks5_session *s = key->data;
    socks5_greeting *g = &s->parsers.greeting;
    buffer *buf = &s->c2p_read;

    size_t space;
    uint8_t *dst = buffer_write_ptr(buf, &space);
    ssize_t r = recv(key->fd, dst, space, 0);
    if (r <= 0) {
        return SOCKS5_CLOSING;
    }
    buffer_write_adv(buf, r);

    size_t avail;
    uint8_t *ptr = buffer_read_ptr(buf, &avail);
    while (avail > 0) {
        uint8_t b = *ptr;
        switch (g->bytes_read) {
          case 0:
            if ((g->req.version = b) != 0x05)  return SOCKS5_ERROR;
            break;
          case 1:
            if ((g->req.nmethods = b) == 0)    return SOCKS5_ERROR;
            break;
          default:
            if (g->bytes_read - 2 < g->req.nmethods)
                g->req.methods[g->bytes_read - 2] = b;
            break;
        }
        g->bytes_read++;
        buffer_read_adv(buf, 1);  ptr++;  avail--;

        if (g->bytes_read == 2 + g->req.nmethods) {
            g->rep.version = 0x05;
            g->rep.method = NO_ACCEPTABLE_METHODS;
            for (uint8_t i = 0; i < g->req.nmethods; i++) {
              if (g->req.methods[i] == NO_AUTH) { g->rep.method = NO_AUTH; break; }
              if (g->req.methods[i] == USER_PASS) g->rep.method = USER_PASS;
            }
            uint8_t reply[2] = { g->rep.version, g->rep.method };
            for (size_t i = 0; i < sizeof(reply); i++)
                buffer_write(&s->p2c_write, reply[i]);
            selector_set_interest_key(key, OP_WRITE);
            return (g->rep.method == NO_ACCEPTABLE_METHODS)
                   ? SOCKS5_ERROR
                   : SOCKS5_GREETING_REPLY;
        }
    }

    return SOCKS5_GREETING;  
}


static unsigned on_greet_write(struct selector_key *key) {
    socks5_session *s = key->data;
    buffer *buf = &s->p2c_write;
    size_t n; uint8_t *ptr = buffer_read_ptr(buf, &n);
    ssize_t sent = send(key->fd, ptr, n, MSG_NOSIGNAL);
    if (sent <= 0) return SOCKS5_CLOSING;
    buffer_read_adv(buf, sent);

    if (!buffer_can_read(buf)) {
        selector_set_interest_key(key, OP_READ);
        if (s->parsers.greeting.rep.method == NO_AUTH) {
            return SOCKS5_REQUEST;
        } else {
            return SOCKS5_METHOD;
        }
    }
    return SOCKS5_GREETING_REPLY;
}


static void on_authentication(const unsigned state, struct selector_key *key) {
    socks5_session *s = key->data;
    authentication_init(&s->parsers.authentication);
}

//AUTH
static unsigned on_authentication_read(struct selector_key *key) {
    socks5_session *s = key->data;
    socks5_authentication *auth = &s->parsers.authentication;
    buffer *buf = &s->c2p_read;
    size_t space;
    uint8_t *dst = buffer_write_ptr(buf, &space);
    ssize_t r = recv(key->fd, dst, space, 0);
    if (r <= 0) {
        return SOCKS5_CLOSING;
    }
    buffer_write_adv(buf, r);


    bool error = false;
    authentication_idx idx = authentication_parse(auth, buf, &error);

    if (error) {
        fprintf(stderr, "Authentication error: invalid request\n");
        return  SOCKS5_ERROR;
    }

    if( idx == AUTHENTICATION_PASSWD) {
        auth->rep.ver = 0x01;
        auth->rep.status = AUTHENTICATION_STATUS_SUCCESS;
        uint8_t reply[2] = { auth->rep.ver, auth->rep.status };
        for (size_t i = 0; i < sizeof(reply); i++)
            buffer_write(&s->p2c_write, reply[i]);
        selector_set_interest_key(key, OP_WRITE);
        return SOCKS5_METHOD_REPLY;
    }
    return SOCKS5_METHOD_REPLY;
}

static unsigned on_authentication_write(struct selector_key *key) {
    socks5_session *s = key->data;
    size_t count; 
    uint8_t *bufptr = buffer_read_ptr(&s->p2c_write, &count);
    ssize_t sent = send(key->fd, bufptr, count, MSG_NOSIGNAL);
    if (sent < 0) {
        return SOCKS5_ERROR;
    }
    buffer_read_adv(&s->p2c_write, sent);
    if (!buffer_can_read(&s->p2c_write)) {
        selector_set_interest_key(key, OP_READ);
        return SOCKS5_REQUEST;
    }
    return SOCKS5_METHOD_REPLY;
}

//REQUEST
static void on_request(const unsigned state, struct selector_key *key) {
    selector_set_interest_key(key, OP_READ);
}

static unsigned on_request_read(struct selector_key *key) {
    socks5_session *s = key->data;
    buffer         *buf = &s->c2p_read;
    size_t          space;
    uint8_t        *dst = buffer_write_ptr(buf, &space);
    ssize_t         nread = recv(key->fd, dst, space, 0);

    if (nread <= 0) {
        return SOCKS5_CLOSING;
    }
    buffer_write_adv(buf, nread);

    size_t avail;
    uint8_t *ptr = buffer_read_ptr(buf, &avail);
    size_t consumed = 0;

    int parse_ret = socks5_parse_request(ptr, avail, &s->parsers.request.request, &consumed);
    if (parse_ret == 0) {
        buffer_read_adv(buf, consumed);

        switch (s->parsers.request.request.cmd) {
            case SOCKS5_CMD_CONNECT:
                return SOCKS5_REQUEST_CONNECT;
            case SOCKS5_CMD_BIND:
                return SOCKS5_REQUEST_BIND;
            case SOCKS5_CMD_UDP_ASSOCIATE:
                return SOCKS5_ERROR;
            default:
                return SOCKS5_ERROR;
        }
    }

    if (avail < 4) {
        return SOCKS5_REQUEST;
    }
    return SOCKS5_ERROR;
}

static int fill_bound_address(int fd, socks5_address *addr) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &sl) < 0) {
        return -1;
    }
    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *in4 = (void *)&ss;
        addr->atyp = SOCKS5_ATYP_IPV4;
        memcpy(addr->addr.ipv4, &in4->sin_addr, 4);
        addr->port = ntohs(in4->sin_port);
    } else if (ss.ss_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (void *)&ss;
        addr->atyp = SOCKS5_ATYP_IPV6;
        memcpy(addr->addr.ipv6, &in6->sin6_addr, 16);
        addr->port = ntohs(in6->sin6_port);
    } else {
        return -1;
    }
    return 0;
}

static unsigned on_request_connect_write(struct selector_key *key) {
    socks5_session *s = key->data;

    socks5_reply rep;
    rep.version = SOCKS5_VERSION;
    rep.rep     = SOCKS5_REP_SUCCEEDED;
    rep.rsv     = 0x00;

    if (fill_bound_address(s->remote_fd, &rep.bnd) < 0) {
        return SOCKS5_ERROR;
    }

    uint8_t *out;
    size_t   outlen;
    if (socks5_build_reply(&rep, &out, &outlen) < 0) {
        return SOCKS5_ERROR;
    }

    for (size_t i = 0; i < outlen; i++) {
        buffer_write(&s->p2c_write, out[i]);
    }
    free(out);

    selector_set_interest_key(key, OP_WRITE);
    return SOCKS5_REQUEST_REPLY;
}

static unsigned on_request_bind_write(struct selector_key *key) {
    socks5_session *s = key->data;

    socks5_reply rep;
    rep.version = SOCKS5_VERSION;
    rep.rep     = SOCKS5_REP_SUCCEEDED;
    rep.rsv     = 0x00;

    if (fill_bound_address(s->remote_fd, &rep.bnd) < 0) {
        return SOCKS5_ERROR;
    }

    uint8_t *out;
    size_t   outlen;
    if (socks5_build_reply(&rep, &out, &outlen) < 0) {
        return SOCKS5_ERROR;
    }
    for (size_t i = 0; i < outlen; i++) {
        buffer_write(&s->p2c_write, out[i]);
    }
    free(out);

    selector_set_interest_key(key, OP_WRITE);
    return SOCKS5_REQUEST_REPLY;
}

static unsigned on_request_forward_read(struct selector_key *key) {
    socks5_session *s = key->data;
    int fd       = key->fd;
    int peer_fd  = (fd == s->client_fd) ? s->remote_fd : s->client_fd;
    buffer *rbuf = (fd == s->client_fd) ? &s->c2p_read : &s->p2c_read;

    size_t space; uint8_t *dst = buffer_write_ptr(rbuf, &space);
    ssize_t n = recv(fd, dst, space, 0);
    if (n <= 0) return SOCKS5_CLOSING;
    buffer_write_adv(rbuf, n);

    selector_set_interest(key->s, peer_fd, OP_WRITE);
    selector_set_interest(key->s, fd, buffer_can_write(rbuf) ? OP_READ : OP_NOOP);
    return SOCKS5_REQUEST_REPLY;
}

static unsigned on_request_forward_write(struct selector_key *key) {
    socks5_session *s = key->data;
    int fd       = key->fd;
    int peer_fd  = (fd == s->client_fd) ? s->remote_fd : s->client_fd;
    buffer *wbuf = (fd == s->client_fd) ? &s->p2c_write : &s->c2p_write;

    size_t n; uint8_t *src = buffer_read_ptr(wbuf, &n);
    ssize_t snt = send(fd, src, n, MSG_NOSIGNAL);
    if (snt <= 0) return SOCKS5_CLOSING;
    buffer_read_adv(wbuf, snt);

    selector_set_interest(key->s, fd, buffer_can_read(wbuf) ? OP_WRITE : OP_NOOP);
    buffer *rbuf = (fd == s->client_fd) ? &s->c2p_read : &s->p2c_read;
    if (buffer_can_write(rbuf)) {
        selector_set_interest(key->s, peer_fd, OP_READ);
    }
    return SOCKS5_REQUEST_REPLY;
}

