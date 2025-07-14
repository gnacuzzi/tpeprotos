#include "include/socks5.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>

extern const struct fd_handler socks5_handler;

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
static unsigned on_request_resolv(struct selector_key *key);
static void on_request_resolv_arrival(const unsigned state, struct selector_key *key);

static void on_stream(const unsigned state, struct selector_key *key);
static unsigned on_closing_read(struct selector_key *key);
static unsigned on_closing_write(struct selector_key *key);

static int init_remote_connection(socks5_session *s, struct selector_key *key);

static int generate_authentication_response(buffer *buf, uint8_t status);

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
        .on_arrival     = on_stream,
        .on_read_ready  = on_request_forward_read,
        .on_write_ready = on_request_forward_write,
    },
    [SOCKS5_ERROR] = {
        .state          = SOCKS5_ERROR,
        .on_read_ready  = on_closing_read,
        .on_write_ready = on_closing_write,
    },
    [SOCKS5_CLOSING] = {
        .state          = SOCKS5_CLOSING,
        .on_read_ready  = on_closing_read,
        .on_write_ready = on_closing_write,
    },
    [SOCKS5_REQUEST_RESOLV] = { 
        .state = SOCKS5_REQUEST_RESOLV, 
        .on_read_ready = on_request_resolv ,
        .on_arrival    = on_request_resolv_arrival,
        .on_block_ready = on_request_resolv,
    },
};

const struct state_definition *get_socks5_states(void) {
  return socks5_states;
}


//GREETING
static void on_greet(const unsigned state, struct selector_key *key) {
    socks5_session *s = key->data;
    fprintf(stderr, "[DEBUG] on_greet: Starting greeting phase for fd=%d\n", key->fd);
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

    fprintf(stderr, "[DEBUG] on_greet_read: Reading greeting data for fd=%d\n", key->fd);

    size_t space;
    uint8_t *dst = buffer_write_ptr(buf, &space);
    ssize_t r = recv(key->fd, dst, space, 0);
    if (r < 0) { 
        perror("recv() in on_greet_read failed");
        fprintf(stderr, "[DEBUG] on_greet_read: recv failed for fd=%d\n", key->fd);
        return SOCKS5_ERROR;
    }
    if (r == 0) { 
        fprintf(stderr, "[DEBUG] on_greet_read: Client (fd=%d) closed connection during greeting\n", key->fd);
        return SOCKS5_CLOSING;
    }
    buffer_write_adv(buf, r);
    fprintf(stderr, "[DEBUG] on_greet_read: Received %zd bytes for fd=%d\n", r, key->fd);

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
            fprintf(stderr, "[DEBUG] on_greet_read: Completed greeting parse, %d methods received\n", g->req.nmethods);
            g->rep.version = 0x05;
            g->rep.method = NO_ACCEPTABLE_METHODS;
            for (uint8_t i = 0; i < g->req.nmethods; i++) {
                fprintf(stderr, "[DEBUG] on_greet_read: Method %d: 0x%02x\n", i, g->req.methods[i]);
                if (g->req.methods[i] == USER_PASS) {
                    g->rep.method = USER_PASS;
                    break;
                }
            }
            fprintf(stderr, "[DEBUG] on_greet_read: Selected method: 0x%02x\n", g->rep.method);
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
    
    fprintf(stderr, "[DEBUG] on_greet_write: Sending greeting response for fd=%d\n", key->fd);
    
    size_t n; uint8_t *ptr = buffer_read_ptr(buf, &n);
    ssize_t sent = send(key->fd, ptr, n, MSG_NOSIGNAL);
    if (sent <= 0) {
        fprintf(stderr, "[DEBUG] on_greet_write: Send failed for fd=%d\n", key->fd);
        return SOCKS5_CLOSING;
    }
    buffer_read_adv(buf, sent);

    if (!buffer_can_read(buf)) {
        selector_set_interest_key(key, OP_READ);
        if (s->parsers.greeting.rep.method == NO_AUTH) {
            fprintf(stderr, "[DEBUG] on_greet_write: No auth required, going to REQUEST state for fd=%d\n", key->fd);
            return SOCKS5_REQUEST;
        } else {
            fprintf(stderr, "[DEBUG] on_greet_write: Auth required, going to METHOD state for fd=%d\n", key->fd);
            return SOCKS5_METHOD;
        }
    }
    return SOCKS5_GREETING_REPLY;
}


static void on_authentication(const unsigned state, struct selector_key *key) {
    socks5_session *s = key->data;
    fprintf(stderr, "[DEBUG] on_authentication: Starting authentication phase for fd=%d\n", key->fd);
    authentication_init(&s->parsers.authentication);
}

//AUTH
static unsigned on_authentication_read(struct selector_key *key) {
    socks5_session *s = key->data;
    socks5_authentication *auth = &s->parsers.authentication;
    buffer *buf = &s->c2p_read;

    fprintf(stderr, "[DEBUG] on_authentication_read: Reading auth data for fd=%d\n", key->fd);

    size_t space;
    uint8_t *dst = buffer_write_ptr(buf, &space);
    ssize_t r = recv(key->fd, dst, space, 0);
    if (r < 0) { 
        perror("recv() in on_authentication_read failed");
        fprintf(stderr, "[DEBUG] on_authentication_read: recv failed for fd=%d\n", key->fd);
        return SOCKS5_ERROR;
    }
    if (r == 0) { 
        fprintf(stderr, "[DEBUG] on_authentication_read: Client (fd=%d) closed connection during authentication\n", key->fd);
        return SOCKS5_CLOSING;
    }
    buffer_write_adv(buf, r);
    fprintf(stderr, "[DEBUG] on_authentication_read: Received %zd bytes for fd=%d\n", r, key->fd);

    bool error = false;
    authentication_idx idx = authentication_parse(auth, buf, &error);

    if (error) {
        fprintf(stderr, "[DEBUG] on_authentication_read: Parse error for fd=%d\n", key->fd);
        generate_authentication_response(&s->p2c_write, AUTHENTICATION_STATUS_FAILED);
        selector_set_interest_key(key, OP_WRITE);
        return SOCKS5_METHOD_REPLY;
    }

    if (idx == AUTHENTICATION_DONE) {
        fprintf(stderr, "[DEBUG] on_authentication_read: Authentication complete for fd=%d\n", key->fd);
        s->user = authenticate_user(&auth->req.cred);
        uint8_t status = (s->user != NULL)
                         ? AUTHENTICATION_STATUS_SUCCESS
                         : AUTHENTICATION_STATUS_FAILED;

          if (status == AUTHENTICATION_STATUS_FAILED) {
            fprintf(stderr, "[DEBUG] Authentication failed for user '%s' on fd %d\n", s->parsers.authentication.req.cred.usernme, key->fd);
        } else {
            fprintf(stderr, "[DEBUG] User '%s' authenticated successfully on fd %d\n", s->user->username, key->fd);
        }

        generate_authentication_response(&s->p2c_write, status);

        selector_set_interest_key(key, OP_WRITE);
        return SOCKS5_METHOD_REPLY;
    }

    return SOCKS5_METHOD;
}

static unsigned on_authentication_write(struct selector_key *key) {
    socks5_session *s = key->data;
    fprintf(stderr, "[DEBUG] on_authentication_write: Sending auth response for fd=%d\n", key->fd);
    
    size_t count; 
    uint8_t *bufptr = buffer_read_ptr(&s->p2c_write, &count);
    ssize_t sent = send(key->fd, bufptr, count, MSG_NOSIGNAL);
    if (sent < 0) {
        fprintf(stderr, "[DEBUG] on_authentication_write: Send failed for fd=%d\n", key->fd);
        return SOCKS5_ERROR;
    }
    buffer_read_adv(&s->p2c_write, sent);
    if (!buffer_can_read(&s->p2c_write)) {
        selector_set_interest_key(key, OP_READ);
        fprintf(stderr, "[DEBUG] on_authentication_write: Auth response sent, transitioning to REQUEST for fd=%d\n", key->fd);
        return SOCKS5_REQUEST;
    }
    return SOCKS5_METHOD_REPLY;
}

static int generate_authentication_response(buffer *buf, uint8_t status) {
    size_t available;
    uint8_t *out = buffer_write_ptr(buf, &available);
    if (available < 2) {
        return -1;
    }
    out[0] = 0x01;    // versión del sub-protocolo
    out[1] = status;  // estado de la autenticación
    buffer_write_adv(buf, 2);
    return 2;
}

//REQUEST
static void on_request(const unsigned state, struct selector_key *key) {
    fprintf(stderr, "[DEBUG] on_request: Starting request phase for fd=%d\n", key->fd);
    selector_set_interest_key(key, OP_READ);
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

static void *dns_resolve_thread(void *arg) {
    struct selector_key *key = arg;
    socks5_session *s = key->data;

    uint16_t port_host = s->parsers.request.request.dst.port;
    char portstr[6];
    snprintf(portstr, sizeof(portstr), "%u", port_host);

    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM
    };
    int rc = getaddrinfo(
        (char*)s->parsers.request.request.dst.addr.domain.name,
        portstr,
        &hints,
        &s->resolved_addr
    );
    if (rc != 0) {
        fprintf(stderr,
                "[DEBUG] dns_resolve_thread: getaddrinfo failed: %s\n",
                gai_strerror(rc));
        s->resolved_addr = NULL;
    }

    selector_notify_block(key->s, key->fd);
    free(arg);
    return NULL;
}

static unsigned on_request_read(struct selector_key *key) {
    socks5_session *s = key->data;
    buffer *buf = &s->c2p_read;
    
    fprintf(stderr, "[DEBUG] on_request_read: Reading request data for fd=%d\n", key->fd);
    
    size_t space;
    uint8_t *dst = buffer_write_ptr(buf, &space);
    ssize_t nread = recv(key->fd, dst, space, 0);
    if (nread <= 0) {
        fprintf(stderr, "[DEBUG] on_request_read: recv failed or connection closed for fd=%d\n", key->fd);
        return SOCKS5_CLOSING;
    }
    buffer_write_adv(buf, nread);
    fprintf(stderr, "[DEBUG] on_request_read: Received %zd bytes for fd=%d\n", nread, key->fd);

    size_t avail;
    uint8_t *ptr = buffer_read_ptr(buf, &avail);
    size_t consumed = 0;
    int ret = socks5_parse_request(ptr, avail, &s->parsers.request.request, &consumed);
    if (ret == 0) {
        fprintf(stderr, "[DEBUG] on_request_read: Request parsed successfully for fd=%d, cmd=%d, atyp=%d\n", 
                key->fd, s->parsers.request.request.cmd, s->parsers.request.request.dst.atyp);
        buffer_read_adv(buf, consumed);
        if (s->parsers.request.request.cmd == SOCKS5_CMD_CONNECT &&
            s->parsers.request.request.dst.atyp == SOCKS5_ATYP_DOMAIN) {
            fprintf(stderr, "[DEBUG] on_request_read: Starting DNS resolution for fd=%d\n", key->fd);
            struct selector_key *k = malloc(sizeof(*k));
            *k = *key;
            pthread_t tid;
            if (pthread_create(&tid, NULL, dns_resolve_thread, k) != 0) {
                fprintf(stderr, "[DEBUG] on_request_read: Failed to create DNS thread for fd=%d\n", key->fd);
                free(k);
                return SOCKS5_ERROR;
            }
            pthread_detach(tid);
            selector_set_interest_key(key, OP_NOOP);
            return SOCKS5_REQUEST_RESOLV;
        }
        switch (s->parsers.request.request.cmd) {
            case SOCKS5_CMD_CONNECT:
                fprintf(stderr, "[DEBUG] on_request_read: Processing CONNECT command for fd=%d\n", key->fd);
                if (init_remote_connection(s, key) < 0) {
                    fprintf(stderr, "[DEBUG] on_request_read: Failed to init remote connection for fd=%d\n", key->fd);
                    socks5_reply rep = {.version = SOCKS5_VERSION, .rep = SOCKS5_REP_HOST_UNREACHABLE, .rsv = 0x00};
                    rep.bnd.atyp = SOCKS5_ATYP_IPV4;
                    memset(rep.bnd.addr.ipv4, 0, 4);
                    rep.bnd.port = 0;
                    uint8_t *out; size_t outlen;
                    socks5_build_reply(&rep, &out, &outlen);
                    for (size_t i = 0; i < outlen; i++) buffer_write(&s->p2c_write, out[i]);
                    free(out);
                    selector_set_interest_key(key, OP_WRITE);
                    return SOCKS5_CLOSING;
                }
                fprintf(stderr, "[DEBUG] on_request_read: Remote connection established, registering fd=%d\n", s->remote_fd);
                selector_set_interest_key(key, OP_NOOP);
                selector_register(key->s, s->remote_fd, &socks5_handler, OP_WRITE, s);
                return SOCKS5_REQUEST_CONNECT;
            case SOCKS5_CMD_BIND:
                fprintf(stderr, "[DEBUG] on_request_read: Processing BIND command for fd=%d\n", key->fd);
                selector_set_interest_key(key, OP_WRITE);
                return SOCKS5_REQUEST_BIND;
            default:
                fprintf(stderr, "[DEBUG] on_request_read: Unsupported command %d for fd=%d\n", s->parsers.request.request.cmd, key->fd);
                return SOCKS5_ERROR;
        }
    }
    fprintf(stderr, "[DEBUG] on_request_read: Request parsing incomplete for fd=%d\n", key->fd);
    return SOCKS5_REQUEST;
}

static void on_request_resolv_arrival(const unsigned state, struct selector_key *key) {
    fprintf(stderr, "[DEBUG] on_request_resolv_arrival: DNS resolution completed for fd=%d\n", key->fd);
    selector_set_interest_key(key, OP_READ);
}


static unsigned on_request_resolv(struct selector_key *key) {
    socks5_session *s = key->data;
    struct addrinfo *res = s->resolved_addr;
    struct addrinfo *p = res;
    while (p) {
        int rfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (rfd >= 0 && selector_fd_set_nio(rfd) == 0) {
            int c = connect(rfd, p->ai_addr, p->ai_addrlen);
            if (c == 0 || (c < 0 && errno == EINPROGRESS)) {
                s->remote_fd = rfd;
                snprintf(s->dest_str, sizeof(s->dest_str), "%s:%u",
                    p->ai_canonname ? p->ai_canonname : "",
                    ntohs(((struct sockaddr_in*)p->ai_addr)->sin_port));
                s->log_id = log_access(s->user ? s->user->username : "<anon>", s->source_ip, s->dest_str, 0);
                selector_register(key->s, rfd, &socks5_handler, OP_WRITE, s);
                freeaddrinfo(res);
                s->resolved_addr = NULL;
                return SOCKS5_REQUEST_CONNECT;
            }
            close(rfd);
        }
        p = p->ai_next;
    }
    freeaddrinfo(res);
    s->resolved_addr = NULL;
    socks5_reply rep = {.version = SOCKS5_VERSION, .rep = SOCKS5_REP_HOST_UNREACHABLE, .rsv = 0x00};
    rep.bnd.atyp = SOCKS5_ATYP_IPV4;
    memset(rep.bnd.addr.ipv4, 0, 4);
    rep.bnd.port = 0;
    uint8_t *out; size_t outlen;
    socks5_build_reply(&rep, &out, &outlen);
    for (size_t i = 0; i < outlen; i++) buffer_write(&s->p2c_write, out[i]);
    free(out);
    return SOCKS5_CLOSING;
}

static unsigned on_request_connect_write(struct selector_key *key) {
    socks5_session *s = key->data;
    int rfd = s->remote_fd;

    fprintf(stderr, "[DEBUG] on_request_connect_write: Checking connection status for fd=%d, remote_fd=%d\n", key->fd, rfd);

    int err=0; socklen_t len=sizeof(err);
    getsockopt(rfd, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err) {
        fprintf(stderr, "[DEBUG] on_request_connect_write: Connection failed for fd=%d, error=%d\n", key->fd, err);
        return SOCKS5_ERROR;
    }

    fprintf(stderr, "[DEBUG] on_request_connect_write: Connection successful for fd=%d\n", key->fd);

    socks5_reply rep = {
      .version = SOCKS5_VERSION,
      .rep     = SOCKS5_REP_SUCCEEDED,
      .rsv     = 0x00
    };
    if (fill_bound_address(rfd, &rep.bnd) < 0) {
        return SOCKS5_ERROR;
    }
    uint8_t *out; size_t outlen;
    socks5_build_reply(&rep, &out, &outlen);
    for (size_t i=0; i<outlen; i++) {
        buffer_write(&s->p2c_write, out[i]);
    }
    free(out);
    s->stm.current = &s->stm.states[SOCKS5_REQUEST_REPLY];
    selector_set_interest(key->s, s->client_fd, OP_WRITE);
    selector_set_interest(key->s, s->remote_fd, OP_READ);
    return SOCKS5_REQUEST_REPLY;
}

static unsigned on_request_bind_write(struct selector_key *key) {
    socks5_session *s = key->data;

    fprintf(stderr, "[DEBUG] on_request_bind_write: Processing BIND response for fd=%d\n", key->fd);

    socks5_reply rep;
    rep.version = SOCKS5_VERSION;
    rep.rep     = SOCKS5_REP_SUCCEEDED;
    rep.rsv     = 0x00;

    if (fill_bound_address(s->remote_fd, &rep.bnd) < 0) {
        fprintf(stderr, "[DEBUG] on_request_bind_write: Failed to get bound address for fd=%d\n", key->fd);
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

static void on_stream(const unsigned state, struct selector_key *key) {
    fprintf(stderr, "[DEBUG] on_stream: Entering stream mode for fd=%d\n", key->fd);
    selector_set_interest_key(key, OP_READ);
}

static unsigned on_request_forward_read(struct selector_key *key) {
    socks5_session *s = key->data;
    int fd      = key->fd;
    int peer_fd = (fd == s->client_fd) ? s->remote_fd
                                       : s->client_fd;
    buffer *wbuf = (fd == s->client_fd) ? &s->c2p_write
                                        : &s->p2c_write;

    fprintf(stderr, "[DEBUG] on_request_forward_read: Forwarding data from fd=%d to fd=%d\n", fd, peer_fd);

    size_t space;
    uint8_t *dst = buffer_write_ptr(wbuf, &space);
    ssize_t n = recv(fd, dst, space, 0);
    if (n <= 0) {
        fprintf(stderr, "[DEBUG] on_request_forward_read: Connection closed or error on fd=%d\n", fd);
        return SOCKS5_CLOSING;
    }

    fprintf(stderr, "[DEBUG] on_request_forward_read: Received %zd bytes from fd=%d\n", n, fd);
    buffer_write_adv(wbuf, n);

    if (s->user != NULL) {
        update_bytes_transferred(s->log_id, n);
        add_bytes_transferred(n);
    }


    selector_set_interest(key->s, peer_fd, OP_WRITE);
    selector_set_interest_key(key,
        buffer_can_write(wbuf) ? OP_READ : OP_NOOP);

    return s->stm.current->state;
}

static unsigned on_request_forward_write(struct selector_key *key) {
    socks5_session *s = key->data;
    int fd      = key->fd;
    int peer_fd = (fd == s->client_fd) ? s->remote_fd
                                       : s->client_fd;
    buffer *rbuf = (fd == s->client_fd) ? &s->p2c_write
                                        : &s->c2p_write;

    fprintf(stderr, "[DEBUG] on_request_forward_write: Writing data to fd=%d from fd=%d\n", fd, peer_fd);

    size_t to_send;
    uint8_t *src = buffer_read_ptr(rbuf, &to_send);
    ssize_t sent = send(fd, src, to_send, MSG_NOSIGNAL);
    if (sent <= 0) {
        fprintf(stderr, "[DEBUG] on_request_forward_write: Send failed on fd=%d\n", fd);
        return SOCKS5_CLOSING;
    }
    fprintf(stderr, "[DEBUG] on_request_forward_write: Sent %zd bytes to fd=%d\n", sent, fd);
    buffer_read_adv(rbuf, sent);

    selector_set_interest(key->s, peer_fd, OP_READ);

    unsigned interest = OP_READ;
    if (buffer_can_read(rbuf)) {
        interest |= OP_WRITE;
    }
    selector_set_interest_key(key, interest);

    if (fd == s->client_fd
        && !buffer_can_read(&s->p2c_write)
        && s->stm.current->state == SOCKS5_REQUEST_REPLY) {
        fprintf(stderr, "[DEBUG] on_request_forward_write: Transitioning to STREAM state for fd=%d\n", fd);
        s->stm.current = &s->stm.states[SOCKS5_STREAM];
        selector_set_interest_key(key, OP_READ);
        selector_register(key->s,
                          s->remote_fd,
                          &socks5_handler,
                          OP_READ,
                          s);
        return SOCKS5_STREAM;
    }

    return s->stm.current->state;
}
static int init_remote_connection(socks5_session *s, struct selector_key *key) {
    socks5_request *req = &s->parsers.request.request;
    char hoststr[INET6_ADDRSTRLEN];
    const char *name;
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM}, *res, *p;

    fprintf(stderr, "[DEBUG] init_remote_connection: Initializing connection for fd=%d\n", key->fd);

    switch (req->dst.atyp) {
      case SOCKS5_ATYP_IPV4:
          inet_ntop(AF_INET, req->dst.addr.ipv4, hoststr, sizeof(hoststr));
          name = hoststr;
          break;
      case SOCKS5_ATYP_IPV6:
          inet_ntop(AF_INET6, req->dst.addr.ipv6, hoststr, sizeof(hoststr));
          name = hoststr;
          break;
      case SOCKS5_ATYP_DOMAIN:
          memcpy(hoststr, req->dst.addr.domain.name, req->dst.addr.domain.len);
          hoststr[req->dst.addr.domain.len] = '\0';
          name = hoststr;
          break;
      default:
          return -1;
    }

    char portstr[6];
    snprintf(portstr, sizeof(portstr), "%u", req->dst.port);

    fprintf(stderr, "[DEBUG] init_remote_connection: Resolving %s:%s for fd=%d\n", name, portstr, key->fd);

    int gai = getaddrinfo(name, portstr, &hints, &res);
    if (gai != 0) {
        fprintf(stderr, "[DEBUG] init_remote_connection: getaddrinfo failed for %s:%s, fd=%d\n", name, portstr, key->fd);
        return -1;
    }

    int rfd = -1;
    bool connected = false;

    for (p = res; p != NULL; p = p->ai_next) {
        rfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (rfd < 0) {
            continue;
        }

        if (selector_fd_set_nio(rfd) == -1) {
            close(rfd);
            continue;
        }

        int c = connect(rfd, p->ai_addr, p->ai_addrlen);
        if (c == 0) {
            fprintf(stderr, "[DEBUG] init_remote_connection: Immediate connection success for fd=%d, remote_fd=%d\n", key->fd, rfd);
            connected = true;
            break;
        }

        if (c < 0 && errno == EINPROGRESS) {
            fprintf(stderr, "[DEBUG] init_remote_connection: Connection in progress for fd=%d, remote_fd=%d\n", key->fd, rfd);
            connected = true;
            break;
        }

        close(rfd);
        rfd = -1;
    }

    freeaddrinfo(res);

    if (!connected) {
        fprintf(stderr, "[DEBUG] init_remote_connection: All connection attempts failed for fd=%d\n", key->fd);
        return -1;
    }

    s->remote_fd = rfd;
    fprintf(stderr, "[DEBUG] init_remote_connection: Connection established for fd=%d, remote_fd=%d\n", key->fd, rfd);

    snprintf(s->dest_str, sizeof(s->dest_str), "%s:%s", name, portstr);
    s->log_id = log_access(s->user ? s->user->username : "<anon>", s->source_ip, s->dest_str, 0);

    return 0;
}


// CLOSING
static unsigned on_closing_read(struct selector_key *key) {
    fprintf(stderr, "[DEBUG] on_closing_read: Handling closing read for fd=%d\n", key->fd);
    return SOCKS5_CLOSING;
}
static unsigned on_closing_write(struct selector_key *key) {
    fprintf(stderr, "[DEBUG] on_closing_write: Handling closing write for fd=%d\n", key->fd);
    return SOCKS5_CLOSING;
}


