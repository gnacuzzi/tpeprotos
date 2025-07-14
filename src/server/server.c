#include "include/socks5.h"
#include "../utils/include/args.h"
#include "./metp/metp.h"
#include <arpa/inet.h> //TODO: chequear que sea legal
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>


#define BUF_SIZE 4096
#define MAX_PORT_STR_LEN 8
#define SELECT_TIMEOUT_SEC 0
#define SELECT_TIMEOUT_NSEC 100000000
#define MAX_SELECTOR_FDS 1024
#define MAX_PORT_VALUE 65535

static void socks5_close(struct selector_key *key) {
    if (key == NULL || key->data == NULL) {
        return;
    }
    socks5_session *s = key->data;
    if (s->is_closing) {
        return;
    }
    s->is_closing = true;
    fprintf(stderr, "Closing SOCKS5 session for fd %d\n", s->client_fd);

    stm_handler_close(&s->stm, key);

    if (s->remote_fd >= 0) {
        selector_unregister_fd(key->s, s->remote_fd);
        close(s->remote_fd);
        s->remote_fd = -1;
    }

    if (s->client_fd >= 0) {
        selector_unregister_fd(key->s, s->client_fd);
        close(s->client_fd);
        decrement_current_connections();
        s->client_fd = -1;
    }

    socks5_request_free(&s->parsers.request.request);
    free(s);
}


static void socks5_read(struct selector_key *key) {
    socks5_session *s = key->data;
    unsigned next = stm_handler_read(&s->stm, key);
    if (next == SOCKS5_CLOSING) {
        socks5_close(key);
        return;
    }
    s->stm.current = &s->stm.states[next];
}

static void metp_read(struct selector_key *key) {
    metp_session *s = key->data;

    if (s == NULL || !s->stm_is_valid) {
        return;
    }

    unsigned next_state = stm_handler_read(&s->stm, key);
    s->stm.current = &s->stm.states[next_state];
}

static void socks5_write(struct selector_key *key) {
    socks5_session *s = key->data;
    unsigned next = stm_handler_write(&s->stm, key);
    if (next == SOCKS5_CLOSING) {
        socks5_close(key);
        return;
    }
    s->stm.current = &s->stm.states[next];
}

static void metp_write(struct selector_key *key) {
    metp_session *s = key->data;

    if (s == NULL) return;

    unsigned next_state = stm_handler_write(&s->stm, key);

    if (next_state == METP_DONE) {
        s->stm_is_valid = false;
        selector_unregister_fd(key->s, key->fd);
        close(key->fd);
        free(s->raw_read_buffer);
        free(s->raw_write_buffer);
        free(s);
        key->data = NULL;
        fprintf(stderr, "Closing METP session for fd %d\n", key->fd);
        return;
    }

    s->stm.current = &s->stm.states[next_state];
}


static void socks5_block(struct selector_key *key) {
    socks5_session *s = key->data;
    unsigned next_state = stm_handler_block(&s->stm, key);
    s->stm.current = &s->stm.states[next_state];
}

static void metp_block(struct selector_key *key) {
    metp_session *s = key->data;
    unsigned next_state = stm_handler_block(&s->stm, key);
    s->stm.current = &s->stm.states[next_state];
}

static const struct fd_handler metp_handler = {
    .handle_read  = metp_read,
    .handle_write = metp_write,
    .handle_block = metp_block, 
};

static void accept_metp(struct selector_key *key) {
    int client_fd = accept(key->fd, NULL, NULL);
    if (client_fd < 0) {
        perror("Failed to accept METP connection");
        return;
    }
    if (fcntl(client_fd, F_SETFL, O_NONBLOCK) < 0) {
        perror("Failed to set METP socket non-blocking");
        close(client_fd);
        return;
    }

    metp_session *m = calloc(1, sizeof(*m));
    if (m == NULL) {
        perror("Failed to allocate METP session");
        close(client_fd);
        return;
    }
    m->stm_is_valid = true;
    m->sockfd           = client_fd;
    m->is_connected     = true;
    m->is_authenticated = false;
    m->must_close = false;

    size_t size = get_io_buffer_size();
    m->raw_read_buffer = malloc(size);
    m->raw_write_buffer = malloc(size);
    m->buffer_size = size;

    if (!m->raw_read_buffer || !m->raw_write_buffer) {
        perror("Failed to allocate METP buffers");
        close(client_fd);
        free(m->raw_read_buffer);
        free(m->raw_write_buffer);
        free(m);
        return;
    }

    buffer_init(&m->read_buffer, size, m->raw_read_buffer);
    buffer_init(&m->write_buffer, size, m->raw_write_buffer);

    m->stm.states    = get_metp_states();
    m->stm.initial   = METP_HELLO;
    m->stm.max_state = METP_DONE;
    stm_init(&m->stm);

    if (selector_register(key->s, client_fd, &metp_handler, OP_READ, m) != SELECTOR_SUCCESS) {
        perror("Failed to register METP session with selector");
        close(client_fd);
        free(m->raw_read_buffer);
        free(m->raw_write_buffer);
        free(m);
        return;
    }

    if (m->stm.states[METP_HELLO].on_arrival) {
        struct selector_key sk = *key;
        sk.fd   = client_fd;
        sk.data = m;
        m->stm.states[METP_HELLO].on_arrival(METP_HELLO, &sk);
    }
}

static const struct fd_handler accept_metp_handler = {
    .handle_read = accept_metp
};

const struct fd_handler socks5_handler = {
    .handle_read  = socks5_read,
    .handle_write = socks5_write,
    .handle_block = socks5_block, 
    .handle_close = socks5_close,
};

static void accept_socks5(struct selector_key *key) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    int client_fd = accept(key->fd, (struct sockaddr *)&ss, &sl);
    if (client_fd == -1) {
        perror("Failed to accept SOCKS5 connection");
        return;
    }
    
    if (fcntl(client_fd, F_SETFL, O_NONBLOCK) == -1) {
        perror("Failed to set SOCKS5 socket non-blocking");
        close(client_fd);
        return;
    }

    // Inicializo sólo la sesión SOCKS5
    socks5_session *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        perror("Failed to allocate SOCKS5 session");
        close(client_fd);
        return;
    }
    
    s->client_fd = client_fd;  s->remote_fd = -1;  s->is_closing = false;
    buffer_init(&s->c2p_read,  BUF_SIZE, s->raw_c2p_r);
    buffer_init(&s->c2p_write, BUF_SIZE, s->raw_c2p_w);
    buffer_init(&s->p2c_read,  BUF_SIZE, s->raw_p2c_r);
    buffer_init(&s->p2c_write, BUF_SIZE, s->raw_p2c_w);
    s->stm.states    = get_socks5_states();
    s->stm.initial   = SOCKS5_GREETING;
    s->stm.max_state = SOCKS5_REQUEST_RESOLV;
    stm_init(&s->stm);

    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *in4 = (void*)&ss;
        inet_ntop(AF_INET, &in4->sin_addr, s->source_ip, sizeof s->source_ip);
    } else if (ss.ss_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (void*)&ss;
        inet_ntop(AF_INET6, &in6->sin6_addr, s->source_ip, sizeof s->source_ip);
    }
    s->bytes_transferred = 0;

    if (selector_register(key->s, client_fd, &socks5_handler, OP_READ, s) != SELECTOR_SUCCESS) {
        fprintf(stderr, "Failed to register SOCKS5 client fd\n");
        free(s);
        close(client_fd);
        return;
    }

    increment_current_connections();
    increment_historic_connections();
}

static const struct fd_handler accept_socks5_handler = {
    .handle_read = accept_socks5
};

int create_listener(const char *addr, const char *port) {
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE,
    }, *res;

    if (getaddrinfo(addr, port, &hints, &res) != 0) {
        perror("getaddrinfo failed");
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd == -1) {
        perror("Failed to create socket");
        freeaddrinfo(res);
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("Failed to set SO_REUSEADDR");
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    
    if (bind(fd, res->ai_addr, res->ai_addrlen) == -1) {
        perror("Failed to bind socket");
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    
    if (listen(fd, SOMAXCONN) == -1) {
        perror("Failed to listen on socket");
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    
    freeaddrinfo(res);
    return fd;
}
int main(int argc, char ** argv) {
    signal(SIGPIPE, SIG_IGN); 

    struct socks5args args;
    parse_args(argc, argv, &args);

    init_metrics();
    init_users();

    for (int i = 0; i < args.nusers; i++) {
        const struct user *u = &args.users[i];
        add_user(u->username, u->password, u->role);
    }

    selector_init(&(struct selector_init){
        .signal = SIGALRM,
        .select_timeout.tv_sec = SELECT_TIMEOUT_SEC,
        .select_timeout.tv_nsec = SELECT_TIMEOUT_NSEC
    });

    fd_selector sel = selector_new(MAX_SELECTOR_FDS);
    if (sel == NULL) {
        perror("Failed to create selector");
        return 1;
    }

    char socks_port_str[MAX_PORT_STR_LEN], mng_port_str[MAX_PORT_STR_LEN];

    if (args.socks_port > MAX_PORT_VALUE || args.mng_port > MAX_PORT_VALUE) {
        fprintf(stderr, "Port number exceeds %d\n", MAX_PORT_VALUE);
        return 1;
    }
    if (snprintf(socks_port_str, sizeof socks_port_str, "%u", args.socks_port) >= sizeof socks_port_str ||
    snprintf(mng_port_str, sizeof mng_port_str, "%u", args.mng_port) >= sizeof mng_port_str) {
        fprintf(stderr, "Port string truncated.\n");
        return 1;
    }

    // 1) Listener SOCKS5
    int s5_fd = create_listener(args.socks_addr, socks_port_str);
    if (s5_fd == -1) {
        fprintf(stderr, "Failed to create SOCKS5 listener on %s:%s\n", args.socks_addr, socks_port_str);
        selector_destroy(sel);
        return 1;
    }
    
    if (fcntl(s5_fd, F_SETFL, O_NONBLOCK) == -1) {
        perror("Failed to set SOCKS5 listener non-blocking");
        close(s5_fd);
        selector_destroy(sel);
        return 1;
    }
    
    if (selector_register(sel, s5_fd, &accept_socks5_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        perror("Failed to register SOCKS5 listener");
        close(s5_fd);
        selector_destroy(sel);
        return 1;
    }

    // 2) Listener METP
    int m_fd = create_listener(args.mng_addr, mng_port_str);
    if (m_fd == -1) {
        fprintf(stderr, "Failed to create METP listener on %s:%s\n", args.mng_addr, mng_port_str);
        close(s5_fd);
        selector_destroy(sel);
        return 1;
    }
    
    if (fcntl(m_fd, F_SETFL, O_NONBLOCK) == -1) {
        perror("Failed to set METP listener non-blocking");
        close(s5_fd);
        close(m_fd);
        selector_destroy(sel);
        return 1;
    }
    
    if (selector_register(sel, m_fd, &accept_metp_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        perror("Failed to register METP listener");
        close(s5_fd);
        close(m_fd);
        selector_destroy(sel);
        return 1;
    }

    while (1) {
        selector_select(sel);
    }
    

    selector_destroy(sel);
    close(s5_fd);
    close(m_fd);
    free_users();
    return 0;
}

