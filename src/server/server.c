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


#define BUF_SIZE 4096
#define S5_PORT "1080"
#define METP_PORT "8080"

//TODO: global del archivo, programacion defensiva, mejorar manejo de errores

//TODO: mejorar close
static void socks5_close(struct selector_key *key) {
    socks5_session *s = key->data;
    if (s->is_closing) {
        return;  
    }
    s->is_closing = true;
    stm_handler_close(&s->stm, key);
    selector_unregister_fd(key->s, s->client_fd);
    if(s->client_fd >= 0) {
        decrement_current_connections();
    }
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

static void metp_read(struct selector_key *key) {
    metp_session *s = key->data;
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
        fprintf(stderr, "[DEBUG] metp_write: no actualizo current porque es DONE\n");

        selector_unregister_fd(key->s, key->fd);
        close(key->fd);
        fprintf(stderr, "[DEBUG] metp_write: liberando sess (sock=%d)\n", key->fd);
        if (s->raw_read_buffer != NULL) {
            free(s->raw_read_buffer);
            s->raw_read_buffer = NULL;
        }
        if (s->raw_write_buffer != NULL) {
            free(s->raw_write_buffer);
            s->raw_write_buffer = NULL;
        }
        free(s);
        key->data = NULL;

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

static void metp_close(struct selector_key *key) {
    metp_session *s = key->data;
    stm_handler_close(&s->stm, key);

    if (s->raw_read_buffer != NULL) {
        free(s->raw_read_buffer);
        s->raw_read_buffer = NULL;
    }
    if (s->raw_write_buffer != NULL) {
        free(s->raw_write_buffer);
        s->raw_write_buffer = NULL;
    }

}

static const struct fd_handler metp_handler = {
    .handle_read  = metp_read,
    .handle_write = metp_write,
    .handle_block = metp_block, 
    .handle_close = metp_close,
};

static void accept_metp(struct selector_key *key) {
    int client_fd = accept(key->fd, NULL, NULL);
    fcntl(client_fd, F_SETFL, O_NONBLOCK);

    metp_session *m = calloc(1, sizeof(*m));
    m->sockfd           = client_fd;
    m->is_connected     = true;
    m->is_authenticated = false;
    m->must_close = false;

    size_t size = get_io_buffer_size();
    m->raw_read_buffer = malloc(size);
    m->raw_write_buffer = malloc(size);
    m->buffer_size = size;

    //aca creo q deberia ir un mensaje de error
    if (!m->raw_read_buffer || !m->raw_write_buffer) {
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

    selector_register(key->s, client_fd, &metp_handler, OP_READ, m);

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
    int client_fd = accept(key->fd, NULL, NULL);
    fcntl(client_fd, F_SETFL, O_NONBLOCK);

    // Inicializo sólo la sesión SOCKS5
    socks5_session *s = calloc(1, sizeof(*s));
    s->client_fd = client_fd;  s->remote_fd = -1;  s->is_closing = false;
    buffer_init(&s->c2p_read,  BUF_SIZE, s->raw_c2p_r);
    buffer_init(&s->c2p_write, BUF_SIZE, s->raw_c2p_w);
    buffer_init(&s->p2c_read,  BUF_SIZE, s->raw_p2c_r);
    buffer_init(&s->p2c_write, BUF_SIZE, s->raw_p2c_w);
    s->stm.states    = get_socks5_states();
    s->stm.initial   = SOCKS5_GREETING;
    s->stm.max_state = SOCKS5_CLOSING;
    stm_init(&s->stm);

    increment_current_connections();
    increment_historic_connections();
    //TODO: dios mio revisa suena a que esta muy mal esto y que el accept no deberia tener
    //de parametros NULL, NULL
    struct sockaddr_storage ss; socklen_t sl = sizeof ss;
    if (getpeername(client_fd, (struct sockaddr*)&ss, &sl) == 0) {
        if (ss.ss_family == AF_INET) {
            struct sockaddr_in *in4 = (void*)&ss;
            inet_ntop(AF_INET, &in4->sin_addr, s->source_ip, sizeof s->source_ip);
        } else {
            struct sockaddr_in6 *in6 = (void*)&ss;
            inet_ntop(AF_INET6, &in6->sin6_addr, s->source_ip, sizeof s->source_ip);
        }
    }
    s->bytes_transferred = 0;

    selector_register(key->s, client_fd, &socks5_handler, OP_READ, s);
}

static const struct fd_handler accept_socks5_handler = {
    .handle_read = accept_socks5
};

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

int main(int argc, char ** argv) {
    signal(SIGPIPE, SIG_IGN); 

    struct socks5args args;
    parse_args(argc, argv, &args);

    init_metrics();
    init_users();

    selector_init(&(struct selector_init){.signal = SIGALRM});
    fd_selector sel = selector_new(1024); //magic number

    // 1) Listener SOCKS5
    int s5_fd = create_listener(S5_PORT);
    fcntl(s5_fd, F_SETFL, O_NONBLOCK);
    selector_register(sel, s5_fd, &accept_socks5_handler, OP_READ, NULL);

    // 2) Listener METP
    int m_fd = create_listener(METP_PORT);
    fcntl(m_fd, F_SETFL, O_NONBLOCK);
    selector_register(sel, m_fd, &accept_metp_handler, OP_READ, NULL);

    while (1) {
        selector_select(sel);
    }

    selector_destroy(sel);
    close(s5_fd);
    close(m_fd);
    free_users(args.users, MAX_USERS);
    return 0;
}