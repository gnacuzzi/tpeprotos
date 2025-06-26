#include "include/socks5.h"

static void on_greet(const unsigned state, struct selector_key *key);
static unsigned on_greet_read   (struct selector_key *key);
static unsigned on_greet_write  (struct selector_key *key);
static void on_authentication(const unsigned state, struct selector_key *key);
static unsigned on_authentication_read(struct selector_key *key);
static unsigned on_authentication_write(struct selector_key *key);

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
    }
};

const struct state_definition *get_socks5_states(void) {
  return socks5_states;
}


//faltan un monton de cosas
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
    size_t n; uint8_t *ptr;

    ptr = buffer_read_ptr(buf, &n);
    ssize_t sent = send(key->fd, ptr, n, MSG_NOSIGNAL); //no es bloquante no?
    if (sent <= 0) {
        return SOCKS5_CLOSING;
    }
    buffer_read_adv(buf, sent);

    if (!buffer_can_read(buf)) {
        return SOCKS5_REQUEST;
    }
    return SOCKS5_GREETING_REPLY;
}

static void on_authentication(const unsigned state, struct selector_key *key) {
    socks5_session *s = key->data;
    authentication_init(&s->parsers.authentication);
}

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
    uint8_t * bufptr = buffer_read_ptr(&s->c2p_write, &count);
    ssize_t sent = send(key->fd, bufptr, count, MSG_NOSIGNAL);
    if( sent < 0) {
        return SOCKS5_ERROR;
    }
    buffer_read_adv(&s->c2p_write, sent);
    if (!buffer_can_read(&s->c2p_write)) {
        if( s->parsers.authentication.rep.status == AUTHENTICATION_STATUS_SUCCESS) {
            return SOCKS5_REQUEST;
        }
        return SOCKS5_ERROR;
    }
    return SOCKS5_REQUEST;
}