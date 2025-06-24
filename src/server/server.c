#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>

#include "../utils/include/selector.h"
#include "../utils/include/buffer.h"

#define BUF_SIZE 4096
#define PORT "1080"

typedef struct {
    buffer read_buf;
    buffer write_buf;
    uint8_t raw_r[BUF_SIZE];
    uint8_t raw_w[BUF_SIZE];
} echo_data;


static void echo_read(struct selector_key *key);
static void echo_write(struct selector_key *key);
static void echo_close(struct selector_key *key);
static void accept_conn(struct selector_key *key);

static const struct fd_handler echo_handler = {
    .handle_read  = echo_read,
    .handle_write = echo_write,
    .handle_close = echo_close,
};

static const struct fd_handler accept_handler = {
    .handle_read = accept_conn,
};

static void echo_read(struct selector_key *key) {
    echo_data *d = key->data;
    size_t n;
    uint8_t *ptr = buffer_write_ptr(&d->read_buf, &n);
    ssize_t r = recv(key->fd, ptr, n, 0);

    if (r <= 0) {
        selector_unregister_fd(key->s, key->fd);
        return;
    }

    buffer_write_adv(&d->read_buf, r);

    // Inicializá el write_buf con el mismo contenido
    buffer_reset(&d->write_buf);
    size_t read_n;
    uint8_t *read_ptr = buffer_read_ptr(&d->read_buf, &read_n);
    memcpy(d->raw_w, read_ptr, read_n);
    buffer_init(&d->write_buf, BUF_SIZE, d->raw_w);
    buffer_write_adv(&d->write_buf, read_n);

    selector_set_interest_key(key, OP_WRITE);
}


static void echo_write(struct selector_key *key) {
    echo_data *d = key->data;
    size_t n;
    uint8_t *ptr = buffer_read_ptr(&d->write_buf, &n);
    ssize_t w = send(key->fd, ptr, n, MSG_NOSIGNAL);

    if (w <= 0) {
        selector_unregister_fd(key->s, key->fd);
        return;
    }

    buffer_read_adv(&d->write_buf, w);

    if (!buffer_can_read(&d->write_buf)) {
        selector_set_interest_key(key, OP_READ);
    }
    buffer_reset(&d->read_buf);

}

static void echo_close(struct selector_key *key) {
    echo_data *d = key->data;
    if (d) free(d);
    close(key->fd);
}

static void accept_conn(struct selector_key *key) {
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    int client_fd = accept(key->fd, (struct sockaddr *) &addr, &len);
    if (client_fd < 0) return;

    fcntl(client_fd, F_SETFL, O_NONBLOCK);

    echo_data *d = calloc(1, sizeof(*d));
    buffer_init(&d->read_buf, BUF_SIZE, d->raw_r);
    buffer_init(&d->write_buf, BUF_SIZE, d->raw_w);

    selector_register(key->s, client_fd, &echo_handler, OP_READ, d);
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
    fd_selector sel = selector_new(1024);
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

