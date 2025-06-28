#include "include/socks5.h"

#define BUF_SIZE 4096
#define PORT "1080"

static void accept_conn(struct selector_key *key);

//no se si estan bien estas
static void socks5_close(struct selector_key *key) {
    socks5_session *s = key->data;
    if (s->is_closing) {
        return;  
    }
    s->is_closing = true;
    stm_handler_close(&s->stm, key);
    selector_unregister_fd(key->s, s->client_fd);
    close(s->client_fd);
    if (s->remote_fd >= 0) {
        selector_unregister_fd(key->s, s->remote_fd);
        close(s->remote_fd);
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

static void socks5_write(struct selector_key *key) {
    socks5_session *s = key->data;
    unsigned next = stm_handler_write(&s->stm, key);
    if (next == SOCKS5_CLOSING) {
        socks5_close(key);
        return;
    }
    s->stm.current = &s->stm.states[next];
}

static void socks5_block(struct selector_key *key) {
    socks5_session *s = key->data;
    unsigned next_state = stm_handler_block(&s->stm, key);
    s->stm.current = &s->stm.states[next_state];
}


const struct fd_handler socks5_handler = {
    .handle_read  = socks5_read,
    .handle_write = socks5_write,
    .handle_block = socks5_block, 
    .handle_close = socks5_close,
};

static const struct fd_handler accept_handler = {
    .handle_read = accept_conn,
};


static void accept_conn(struct selector_key *key) {
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    int client_fd = accept(key->fd, (struct sockaddr*)&addr, &len);
    if (client_fd < 0) return;
    fcntl(client_fd, F_SETFL, O_NONBLOCK);

    socks5_session *s = calloc(1, sizeof(*s));
    s->client_fd = client_fd;
    s->remote_fd = -1;
    s->is_closing = false;
    buffer_init(&s->c2p_read, BUF_SIZE, s->raw_c2p_r);
    buffer_init(&s->c2p_write, BUF_SIZE, s->raw_c2p_w);
    buffer_init(&s->p2c_read, BUF_SIZE, s->raw_p2c_r);
    buffer_init(&s->p2c_write, BUF_SIZE, s->raw_p2c_w);

    const struct state_definition *socks5_states = get_socks5_states();
    s->stm.states = socks5_states;
    s->stm.initial = SOCKS5_GREETING;
    s->stm.max_state = SOCKS5_CLOSING; 
    stm_init(&s->stm);

    selector_register(key->s, client_fd, &socks5_handler, OP_READ, s);

    if (socks5_states[SOCKS5_GREETING].on_arrival) {
      struct selector_key sk = *key;
      sk.fd = client_fd;
      sk.data = s;
      socks5_states[SOCKS5_GREETING].on_arrival(SOCKS5_GREETING, &sk);
    }
}


int create_listener(const char *port) {
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE,
    }, *res;

    if (getaddrinfo(NULL, port, &hints, &res) != 0) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    bind(fd, res->ai_addr, res->ai_addrlen);
    listen(fd, SOMAXCONN);
    freeaddrinfo(res);
    return fd;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN); 

    selector_init(&(struct selector_init){.signal = SIGALRM});
    fd_selector sel = selector_new(1024); //magic number
    int server_fd = create_listener(PORT);
    fcntl(server_fd, F_SETFL, O_NONBLOCK);

    selector_register(sel, server_fd, &accept_handler, OP_READ, NULL);

    while (1) {
        selector_select(sel);
    }

    selector_destroy(sel);
    close(server_fd);
    return 0;
}

