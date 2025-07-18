#include "include/socks5.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

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
    s->parsers.greeting.req.version = SOCKS5_VERSION; 
    s->parsers.greeting.req.nmethods = 0; 
    s->parsers.greeting.bytes_read = 0;
    s->parsers.greeting.bytes_written = 0;

    s->parsers.greeting.rep.version = SOCKS5_VERSION; 
    s->parsers.greeting.rep.method = NO_ACCEPTABLE_METHODS; 
}

static unsigned on_greet_read(struct selector_key *key) {
    socks5_session *s = key->data;
    socks5_greeting *g = &s->parsers.greeting;
    buffer *buf = &s->c2p_read;

    size_t space;
    uint8_t *dst = buffer_write_ptr(buf, &space);
    ssize_t r = recv(key->fd, dst, space, 0);
    if (r < 0) { 
        perror("recv() in on_greet_read failed");
        return SOCKS5_ERROR;
    }
    if (r == 0) { 
        return SOCKS5_CLOSING;
    }
    buffer_write_adv(buf, r);

    size_t avail;
    uint8_t *ptr = buffer_read_ptr(buf, &avail);
    while (avail > 0) {
        uint8_t b = *ptr;
        switch (g->bytes_read) {
          case 0:
            if ((g->req.version = b) != SOCKS5_VERSION)  return SOCKS5_ERROR;
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
            g->rep.version = SOCKS5_VERSION;
            g->rep.method = NO_ACCEPTABLE_METHODS;
            for (uint8_t i = 0; i < g->req.nmethods; i++) {
                if (g->req.methods[i] == USER_PASS) {
                    g->rep.method = USER_PASS;
                    break;
                }
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
    if (sent <= 0) {
        return SOCKS5_CLOSING;
    }
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
    if (r < 0) { 
        perror("recv() in on_authentication_read failed");
        return SOCKS5_ERROR;
    }
    if (r == 0) { 
        return SOCKS5_CLOSING;
    }
    buffer_write_adv(buf, r);

    bool error = false;
    authentication_idx idx = authentication_parse(auth, buf, &error);

    if (error) {
        generate_authentication_response(&s->p2c_write, AUTHENTICATION_STATUS_FAILED);
        selector_set_interest_key(key, OP_WRITE);
        return SOCKS5_METHOD_REPLY;
    }

    if (idx == AUTHENTICATION_DONE) {
        struct user *u = authenticate_user(&auth->req.cred);
        s->user = u;
        s->auth_status = (u != NULL)
                          ? AUTHENTICATION_STATUS_SUCCESS
                          : AUTHENTICATION_STATUS_FAILED;

        generate_authentication_response(&s->p2c_write, s->auth_status);
        selector_set_interest_key(key, OP_WRITE);

        return SOCKS5_METHOD_REPLY;
    }

    return SOCKS5_METHOD;
}


static unsigned on_authentication_write(struct selector_key *key) {
    socks5_session *s = key->data;
    buffer *w = &s->p2c_write;

    size_t to_send; 
    uint8_t *bufptr = buffer_read_ptr(w, &to_send);
    ssize_t sent = send(key->fd, bufptr, to_send, MSG_NOSIGNAL);
    if (sent <= 0) {
        return SOCKS5_CLOSING;
    }
    buffer_read_adv(w, sent);

    if (!buffer_can_read(w)) {
        if (s->auth_status == AUTHENTICATION_STATUS_FAILED) {
            return SOCKS5_CLOSING;
        } else {
            selector_set_interest_key(key, OP_READ);
            return SOCKS5_REQUEST;
        }
    }

    return SOCKS5_METHOD_REPLY;
}

static int generate_authentication_response(buffer *buf, uint8_t status) {
    size_t available;
    uint8_t *out = buffer_write_ptr(buf, &available);
    if (available < 2) {
        return -1;
    }
    out[0] = SOCKS5_ATYP_IPV4;   
    out[1] = status; 
    buffer_write_adv(buf, 2);
    return 2;
}

//REQUEST
static void on_request(const unsigned state, struct selector_key *key) {
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
        s->resolved_addr = NULL;
    }

    selector_notify_block(key->s, key->fd);
    free(arg);
    return NULL;
}

static unsigned on_request_read(struct selector_key *key) {
    socks5_session *s = key->data;
    buffer *buf = &s->c2p_read;
    
    size_t space;
    uint8_t *dst = buffer_write_ptr(buf, &space);
    ssize_t nread = recv(key->fd, dst, space, 0);
    if (nread <= 0) {
        return SOCKS5_CLOSING;
    }
    buffer_write_adv(buf, nread);

    size_t avail;
    uint8_t *ptr = buffer_read_ptr(buf, &avail);
    size_t consumed = 0;
    int ret = socks5_parse_request(ptr, avail, &s->parsers.request.request, &consumed);
    if (ret == 0) {
        buffer_read_adv(buf, consumed);
        switch (s->parsers.request.request.cmd) {
            case SOCKS5_CMD_CONNECT:
                switch (s->parsers.request.request.dst.atyp)
                {
                    case SOCKS5_ATYP_DOMAIN: {
                        struct selector_key *k = malloc(sizeof(struct selector_key));
                        *k = *key;
                        pthread_t tid;
                        if (pthread_create(&tid, NULL, dns_resolve_thread, k) != 0) {
                            free(k);
                            return SOCKS5_ERROR;
                        }
                        pthread_detach(tid);
                        selector_set_interest_key(key, OP_NOOP);
                        return SOCKS5_REQUEST_RESOLV;
                    }            
                    case SOCKS5_ATYP_IPV4: {
                        s->remote_domain   = AF_INET;
                        s->remote_addr_len = sizeof(struct sockaddr_in);
                        struct sockaddr_in *addr4 = (struct sockaddr_in *)&s->remote_addr;

                        addr4->sin_family = AF_INET;
                        memcpy(&addr4->sin_addr,
                            s->parsers.request.request.dst.addr.ipv4, 4);
                        addr4->sin_port   = htons(s->parsers.request.request.dst.port);

                        char ipbuf[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET,
                                s->parsers.request.request.dst.addr.ipv4,
                                ipbuf, sizeof(ipbuf));

                        return init_remote_connection(s, key);
                    }
                    case SOCKS5_ATYP_IPV6: {
                        s->remote_domain   = AF_INET6;
                        s->remote_addr_len = sizeof(struct sockaddr_in6);
                        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&s->remote_addr;

                        addr6->sin6_family = AF_INET6;
                        memcpy(&addr6->sin6_addr,
                            s->parsers.request.request.dst.addr.ipv6, 16);
                        addr6->sin6_port = htons(s->parsers.request.request.dst.port);

                        char ip6buf[INET6_ADDRSTRLEN];
                        inet_ntop(AF_INET6,
                                s->parsers.request.request.dst.addr.ipv6,
                                ip6buf, sizeof(ip6buf));

                        return init_remote_connection(s, key);
                    }

                }
                selector_set_interest_key(key, OP_NOOP);
                selector_register(key->s, s->remote_fd, &socks5_handler, OP_WRITE, s);
                return SOCKS5_REQUEST_CONNECT;
            case SOCKS5_CMD_BIND:
                selector_set_interest_key(key, OP_WRITE);
                return SOCKS5_REQUEST_BIND;
            default:
                return SOCKS5_ERROR;
        }
    }
    return SOCKS5_REQUEST;
}

static void on_request_resolv_arrival(const unsigned state, struct selector_key *key) {
    selector_set_interest_key(key, OP_READ);
}


static unsigned on_request_resolv(struct selector_key *key) {
    socks5_session *s = key->data;
    struct addrinfo *res = s->resolved_addr;
    struct addrinfo *p = res;

    while (p) {
        s->remote_domain   = p->ai_family;
        s->remote_addr_len = p->ai_addrlen;
        memcpy(&s->remote_addr, p->ai_addr, p->ai_addrlen);

        freeaddrinfo(res);
        s->resolved_addr = NULL;

        return init_remote_connection(s, key);
    }

    freeaddrinfo(res);
    s->resolved_addr = NULL;

    socks5_reply rep = {
      .version = SOCKS5_VERSION,
      .rep     = SOCKS5_REP_HOST_UNREACHABLE,
      .rsv     = 0x00
    };
    rep.bnd.atyp = SOCKS5_ATYP_IPV4;
    memset(rep.bnd.addr.ipv4, 0, 4);
    rep.bnd.port = 0;

    uint8_t *out; size_t outlen;
    socks5_build_reply(&rep, &out, &outlen);
    for (size_t i = 0; i < outlen; i++) {
        buffer_write(&s->p2c_write, out[i]);
    }
    free(out);

    selector_set_interest_key(key, OP_WRITE);

    return SOCKS5_CLOSING;
}

static unsigned on_request_connect_write(struct selector_key *key) {
    socks5_session *s = key->data;
    int rfd = s->remote_fd;

    int err=0; socklen_t len=sizeof(err);
    if(getsockopt(rfd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
        perror("getsockopt");
        return SOCKS5_ERROR;

    }
    if (err) {
        return SOCKS5_ERROR;
    }

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

static void on_stream(const unsigned state, struct selector_key *key) {
    selector_set_interest_key(key, OP_READ);
}

static unsigned on_request_forward_read(struct selector_key *key) {
    socks5_session *s = key->data;
    int fd      = key->fd;
    int peer_fd = (fd == s->client_fd) ? s->remote_fd
                                       : s->client_fd;
    buffer *wbuf = (fd == s->client_fd) ? &s->c2p_write
                                        : &s->p2c_write;

    size_t space;
    uint8_t *dst = buffer_write_ptr(wbuf, &space);
    ssize_t n = recv(fd, dst, space, 0);
    if (n <= 0) {
        return SOCKS5_CLOSING;
    }

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

    size_t to_send;
    uint8_t *src = buffer_read_ptr(rbuf, &to_send);
    ssize_t sent = send(fd, src, to_send, MSG_NOSIGNAL);
    if (sent <= 0) {
        return SOCKS5_CLOSING;
    }
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

    switch (req->dst.atyp) {
      case SOCKS5_ATYP_IPV4:
          inet_ntop(AF_INET,  req->dst.addr.ipv4, hoststr, sizeof(hoststr));
          name = hoststr;
          break;
      case SOCKS5_ATYP_IPV6:
          inet_ntop(AF_INET6, req->dst.addr.ipv6, hoststr, sizeof(hoststr));
          name = hoststr;
          break;
      case SOCKS5_ATYP_DOMAIN:
          memcpy(hoststr,
                 req->dst.addr.domain.name,
                 req->dst.addr.domain.len);
          hoststr[req->dst.addr.domain.len] = '\0';
          name = hoststr;
          break;
      default:
          return SOCKS5_ERROR;
    }

    char portstr[6];
    snprintf(portstr, sizeof(portstr), "%u", req->dst.port);

    int sock = socket(s->remote_domain, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return SOCKS5_ERROR;
    }

    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK) < 0) {
        perror("fcntl O_NONBLOCK");
        close(sock);
        return SOCKS5_ERROR;
    }

    int ret = connect(sock,
                      (struct sockaddr *)&s->remote_addr,
                      s->remote_addr_len);
    if (ret < 0 && errno != EINPROGRESS) {
        close(sock);
        return SOCKS5_ERROR;
    }

    s->remote_fd = sock;

    selector_set_interest_key(key, OP_NOOP);
    if (selector_register(key->s, sock, &socks5_handler, OP_WRITE, s)
        != SELECTOR_SUCCESS) {
        close(sock);
        return SOCKS5_ERROR;
    }

    snprintf(s->dest_str, sizeof(s->dest_str), "%s:%s", name, portstr);
    s->log_id = log_access(s->user ? s->user->username : "<anon>", s->source_ip, s->dest_str, 0);

    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    fprintf(stdout,
        "[%04d-%02d-%02dT%02d:%02d:%02dZ] %s %s %s\n",
        tm_info->tm_year + 1900,
        tm_info->tm_mon  + 1,
        tm_info->tm_mday,
        tm_info->tm_hour,
        tm_info->tm_min,
        tm_info->tm_sec,
        s->user ? s->user->username : "<anon>",
        s->source_ip,
        s->dest_str);
    fflush(stdout);

    return SOCKS5_REQUEST_CONNECT;
}

// CLOSING
static unsigned on_closing_read(struct selector_key *key) {
    return SOCKS5_CLOSING;
}
static unsigned on_closing_write(struct selector_key *key) {
    return SOCKS5_CLOSING;
}


