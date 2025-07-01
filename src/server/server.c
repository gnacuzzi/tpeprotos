#include "./metp/metp.h"
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>


#define BUF_SIZE 4096
#define MET_PORT "1080"

static void accept_conn(struct selector_key *key);

static void metp_read(struct selector_key *key) {
    metp_session *s = key->data;
    unsigned next_state = stm_handler_read(&s->stm, key);
    s->stm.current = &s->stm.states[next_state];
}

static void metp_write(struct selector_key *key) {
    metp_session *s = key->data;
    unsigned next_state = stm_handler_write(&s->stm, key);
    s->stm.current = &s->stm.states[next_state];
}

static void metp_block(struct selector_key *key) {
    metp_session *s = key->data;
    unsigned next_state = stm_handler_block(&s->stm, key);
    s->stm.current = &s->stm.states[next_state];
}

static void metp_close(struct selector_key *key) {
    metp_session *s = key->data;
    stm_handler_close(&s->stm, key);
}

static const struct fd_handler metp_handler = {
    .handle_read  = metp_read,
    .handle_write = metp_write,
    .handle_block = metp_block, 
    .handle_close = metp_close,
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

    metp_session *s = calloc(1, sizeof(*s));
    s->sockfd           = client_fd;
    s->is_connected     = true;
    s->is_authenticated = false;
    buffer_init(&s->read_buffer,  BUFFER_SIZE, s->raw_read_buffer);
    buffer_init(&s->write_buffer, BUFFER_SIZE, s->raw_write_buffer);

    const struct state_definition *st = get_metp_states();
    s->stm.states    = st;
    s->stm.initial   = METP_HELLO;
    s->stm.max_state = METP_DONE;
    stm_init(&s->stm);

    selector_register(key->s, client_fd, &metp_handler, OP_READ, s);

    if (st[METP_HELLO].on_arrival) {
        struct selector_key sk = *key;
        sk.fd   = client_fd;
        sk.data = s;
        st[METP_HELLO].on_arrival(METP_HELLO, &sk);
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

    init_metrics();
    init_users();
    selector_init(&(struct selector_init){.signal = SIGALRM});
    fd_selector sel = selector_new(1024); //magic number
    int server_fd = create_listener(MET_PORT);
    fcntl(server_fd, F_SETFL, O_NONBLOCK);

    selector_register(sel, server_fd, &accept_handler, OP_READ, NULL);

    while (1) {
        selector_select(sel);
    }

    selector_destroy(sel);
    close(server_fd);
    return 0;
}