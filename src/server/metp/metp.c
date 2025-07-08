#include "metp.h"

static unsigned on_hello_read(struct selector_key *key);
static unsigned on_hello_write(struct selector_key *key);
static unsigned on_authentication_read(struct selector_key *key);
static unsigned on_authentication_write(struct selector_key *key);
static void on_request(const unsigned state, struct selector_key *key);
static unsigned on_request_read(struct selector_key *key);
static unsigned on_request_write(struct selector_key *key);
static void on_error_arrival(const unsigned state, struct selector_key *key);
static unsigned on_error_write(struct selector_key *key);
static void respuesta_error(const char *msg, struct selector_key *key);

static size_t io_buffer_size = BUFFER_SIZE;

static const struct state_definition metp_states[] = {
    [METP_HELLO] = {
        .state          = METP_HELLO,
        .on_read_ready  = on_hello_read,
    },
    [METP_HELLO_REPLY] = {
        .state          = METP_HELLO_REPLY,
        .on_write_ready = on_hello_write,
    },
    [METP_AUTH] = {
        .state          = METP_AUTH,
        .on_read_ready  = on_authentication_read,
    },
    [METP_AUTH_REPLY] = {
        .state          = METP_AUTH_REPLY,
        .on_write_ready = on_authentication_write,
    },
    [METP_REQUEST] = {
        .state          = METP_REQUEST,
        .on_arrival     = on_request,
        .on_read_ready  = on_request_read,
    },
    [METP_REQUEST_REPLY] = {
        .state          = METP_REQUEST_REPLY,
        .on_write_ready = on_request_write,
    },
    [METP_ERROR] = {
        .state          = METP_ERROR,
        .on_arrival     = on_error_arrival,
        .on_write_ready = on_error_write,
    },
    [METP_DONE] = {
        .state          = METP_DONE,
    }
};

const struct state_definition *get_metp_states(void) {
  return metp_states;
}

static unsigned on_hello_read(struct selector_key *key) {
    metp_session *sess = key->data;
    fprintf(stderr, "[DEBUG] entra en on_hello_read (sock=%d)\n", sess->sockfd);
    fflush(stderr);
    size_t cap;
    unsigned state = METP_ERROR;  

    uint8_t *in = buffer_write_ptr(&sess->read_buffer, &cap);
    ssize_t n = recv(sess->sockfd, in, cap, 0);
    fprintf(stderr, "[DEBUG] recv(%d) devolvió %zd bytes\n", sess->sockfd, n);
    if (n > 0) {
        fprintf(stderr, "[DEBUG] datos recibidos: '%.*s'\n", (int)n, in);
    }
    fflush(stderr);
    if (n <= 0) {
        if (n < 0) perror("recv() en on_hello_read");
        respuesta_error("500 Internal Server Error\n", key);
        fflush(stderr);
        return METP_ERROR;
    }
    buffer_write_adv(&sess->read_buffer, n);

    uint8_t c;
    while (buffer_can_read(&sess->read_buffer)) {
        c = buffer_read(&sess->read_buffer);

        if (sess->parsers.auth.idx < BUFFER_SIZE - 1) {
            sess->parsers.auth.line[sess->parsers.auth.idx++] = (char)c;
        }else {
            state = METP_ERROR;
            const char *resp = "400 Bad Request: Line too long\n";
            respuesta_error(resp, key);
            selector_set_interest_key(key, OP_WRITE);
            return state;
        }

        if (c == '\n' || sess->parsers.auth.idx == BUFFER_SIZE - 1) {
            sess->parsers.auth.line[sess->parsers.auth.idx] = '\0';

            if (strcmp(sess->parsers.auth.line, "HELLO " METP_VERSION "\n") == 0) {
                fprintf(stderr, "[DEBUG] HELLO recibido correctamente\n");
                const char *resp = "200 Welcome to " METP_VERSION "\n";
                size_t wcap;
                uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                fprintf(stderr, "[DEBUG] preparando respuesta: '%s'\n", resp);
                fflush(stderr);
                size_t len = strlen(resp);
                if (len > wcap) len = wcap;
                memcpy(out, resp, len);
                buffer_write_adv(&sess->write_buffer, len);
                fprintf(stderr, "[DEBUG] respuesta escrita en el buffer de escritura\n");
                fflush(stderr);
                selector_set_interest_key(key, OP_WRITE);
                state = METP_HELLO_REPLY;
            } else {
                state = METP_ERROR;
                const char *resp = "400 Bad Request\n";
                size_t wcap;
                uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                size_t len = strlen(resp);
                if (len > wcap) len = wcap;
                memcpy(out, resp, len);
                buffer_write_adv(&sess->write_buffer, len);
                fprintf(stderr, "[DEBUG] respuesta de error escrita en el buffer de escritura\n");
                fflush(stderr);
            }

            sess->parsers.auth.idx = 0;
            break;
        }
    }
    fprintf(stderr, "[DEBUG] sale de on_hello_read con nuevo estado %u\n", state);
    fflush(stderr);

    return state;
}


static unsigned on_hello_write(struct selector_key *key) {
    metp_session *sess = key->data;
    fprintf(stderr, "[DEBUG] entra en on_hello_write (sock=%d)\n", sess->sockfd);
    fflush(stderr);
    size_t count;
    uint8_t *out = buffer_read_ptr(&sess->write_buffer, &count);
    if (count == 0) {
        fprintf(stderr, "[DEBUG] buffer_write_ptr devolvió 0 bytes, estado -> METP_ERROR\n");
        return METP_ERROR;
    }
    ssize_t w = send(sess->sockfd, out, count, 0);
    fprintf(stderr, "[DEBUG] send(%d) devolvió %zd bytes\n", sess->sockfd, w);
    if (w <= 0) {
        if (w < 0) perror("send() en on_hello_write");
        return METP_ERROR;
    }
    buffer_read_adv(&sess->write_buffer, w);

    if (!buffer_can_read(&sess->write_buffer)) {
        selector_set_interest_key(key, OP_READ);
        return METP_AUTH;
    }
    return METP_HELLO_REPLY;
}
static unsigned on_authentication_read(struct selector_key *key) {
    metp_session *sess = key->data;
    fprintf(stderr, "[DEBUG] entra en on_authentication_read (sock=%d)\n", sess->sockfd);
    fflush(stderr);
    size_t cap;
    
    uint8_t *in = buffer_write_ptr(&sess->read_buffer, &cap);
    ssize_t n = recv(sess->sockfd, in, cap, 0);
    if (n <= 0) {
        return METP_ERROR;
    }
    buffer_write_adv(&sess->read_buffer, n);

    uint8_t c;
    while (buffer_can_read(&sess->read_buffer)) {
        c = buffer_read(&sess->read_buffer);

       
        if (sess->parsers.auth.idx >= BUFFER_SIZE - 1) {
            respuesta_error("400 Bad Request: Line too long\n", key);
            selector_set_interest_key(key, OP_WRITE);
            return METP_ERROR;
        }
        
        sess->parsers.auth.line[sess->parsers.auth.idx++] = (char)c;

        if (c == '\n') {
            sess->parsers.auth.line[sess->parsers.auth.idx] = '\0';
            sess->parsers.auth.idx = 0; 

            char *saveptr = NULL;
            char *cmd = strtok_r(sess->parsers.auth.line, " \r\n", &saveptr);
            
            if (cmd == NULL) { 
                continue; 
            }

            if (strcmp(cmd, "AUTH") == 0) {
                char *user = strtok_r(NULL, " \r\n", &saveptr);
                char *pass = strtok_r(NULL, " \r\n", &saveptr);

                if (user == NULL || pass == NULL) {
                    respuesta_error("400 Bad Request: Missing user or password\n", key);
                    selector_set_interest_key(key, OP_WRITE);
                    return METP_ERROR;
                }

                if (verify_user(user, pass)) {
                    sess->is_authenticated = true;
                    strncpy(sess->authenticated_user, user, MAX_USERNAME_LEN - 1);
                    sess->authenticated_user[MAX_USERNAME_LEN - 1] = '\0';
                    respuesta_error("200 OK\n", key); 
                } else {
                    respuesta_error("401 Unauthorized. Closing conection.\n", key);
                    sess->must_close = true; 
                }
                
                selector_set_interest_key(key, OP_WRITE);
                return METP_AUTH_REPLY;

            } else {
                respuesta_error("400 Bad Request\n", key);
                selector_set_interest_key(key, OP_WRITE);
                return METP_ERROR;
            }
        }
    }
    return METP_AUTH;
}

static unsigned on_authentication_write(struct selector_key *key) {
    metp_session *sess = key->data;
    fprintf(stderr, "[DEBUG] entra en on_authentication_write (sock=%d)\n", sess->sockfd);
    fflush(stderr);
    size_t count;

    uint8_t *out = buffer_read_ptr(&sess->write_buffer, &count);
    ssize_t w = send(sess->sockfd, out, count, 0);
    if (w <= 0) {
        return METP_ERROR;
    }
    buffer_read_adv(&sess->write_buffer, w);

    if (!buffer_can_read(&sess->write_buffer)) {
        if (!sess->is_authenticated) {
            close(sess->sockfd);
            return METP_DONE;
        }
        selector_set_interest_key(key, OP_READ);
        return METP_REQUEST;
    }
    return METP_AUTH_REPLY;
}

static void on_request(const unsigned state, struct selector_key *key) {
    metp_session *sess = key->data;
    sess->parsers.request.idx = 0;
    sess->parsers.request.line[0] = '\0';
    selector_set_interest_key(key, OP_READ);
}


static void respuesta_ok(struct selector_key *key) {
    metp_session *sess = key->data;
    const char *r = "200 OK\n";
    size_t wcap; 
    uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
    memcpy(out, r, strlen(r));
    buffer_write_adv(&sess->write_buffer, strlen(r));
    selector_set_interest_key(key, OP_WRITE);
    
}
static void respuesta_error(const char *msg, struct selector_key *key) {
    metp_session *sess = key->data;
    if (sess == NULL) return; 
    size_t wcap; 
    uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
    size_t len = strlen(msg);
    if (len > wcap) len = wcap;
    memcpy(out, msg, len);
    buffer_write_adv(&sess->write_buffer, len);
    selector_set_interest_key(key, OP_WRITE);
}


//TODO: agregar manejo de error tipo 500, quizas seria en el handler error
static unsigned on_request_read(struct selector_key *key) {
    metp_session *sess = key->data;
    fprintf(stderr, "[DEBUG] entra en on_request_read (sock=%d)\n", sess->sockfd);
    fflush(stderr);
    size_t cap;
    unsigned state = METP_ERROR;

    uint8_t *in = buffer_write_ptr(&sess->read_buffer, &cap);
    ssize_t n = recv(sess->sockfd, in, cap, 0);
    if (n < 0) {
        perror("recv() en on_request_read");
        respuesta_error("500 Internal Server Error\n", key);
        selector_set_interest_key(key, OP_WRITE);
        return METP_ERROR;
    }
    if (n == 0) {
        selector_unregister_fd(key->s, sess->sockfd);
        close(sess->sockfd);
        free(sess);
        key->data = NULL;
        return METP_DONE;
    }
    buffer_write_adv(&sess->read_buffer, n);

    uint8_t c;
    while (buffer_can_read(&sess->read_buffer)) {
        c = buffer_read(&sess->read_buffer);
        if (sess->parsers.request.idx < BUFFER_SIZE - 1) {
            sess->parsers.request.line[sess->parsers.request.idx++] = (char)c;
        }else {
            respuesta_error("400 Bad Request: Line too long\n", key);
            selector_set_interest_key(key, OP_WRITE);
            return METP_REQUEST_REPLY;
        }
        if (c == '\n' || sess->parsers.request.idx == BUFFER_SIZE - 1) {
            sess->parsers.request.line[sess->parsers.request.idx] = '\0';

            char *saveptr = NULL;
            char *cmd = strtok_r(sess->parsers.request.line, " \r\n", &saveptr);
            fprintf(stderr, "[DEBUG] comando recibido: '%s'\n", cmd ? cmd : "NULL");

            if (cmd && strcmp(cmd, "GET_METRICS") == 0) {
                if (!can_user_execute_command(sess->authenticated_user, "GET_METRICS")) {
                    respuesta_error("403 Forbidden\n", key);
                } else {
                    static char tmp[128];
                    int len = snprintf(tmp, sizeof(tmp),
                      "200 OK\n"
                      "HISTORICAL_CONNECTIONS: %u\n"
                      "CURRENT_CONNECTIONS:    %u\n"
                      "BYTES_TRANSFERRED:      %" PRIu64 "\n"
                      ".\n",
                      get_historic_connections(),
                      get_socks_current_connections(),
                      get_bytes_transferred()
                    ); 
                    if (len > 0 && len < sizeof(tmp)) {
                        respuesta_error(tmp, key); 
                    } else {
                        respuesta_error("500 Internal Server Error\n", key);
                    }

                    sess->send_ptr = tmp;
                    sess->send_remaining = len;
                    sess->sending_data = true;

                    const char *hdr = "200 OK\n";
                    size_t hlen = strlen(hdr);
                    size_t wcap;
                    uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                    if (wcap >= hlen) {
                        memcpy(out, hdr, hlen);
                        buffer_write_adv(&sess->write_buffer, hlen);
                    }
            }

                state = METP_REQUEST_REPLY;
            }
            else if (strcmp(cmd, "GET_LOGS") == 0) {
                if (!can_user_execute_command(sess->authenticated_user, "GET_LOGS")) {
                    respuesta_error("403 Forbidden\n", key);
                } else {
                    const char *logs_data = get_logs();
                    sess->send_ptr = logs_data;
                    sess->send_remaining = strlen(logs_data);
                    sess->sending_data = true;

                    const char *hdr = "200 OK\n";
                    size_t hlen = strlen(hdr);
                    size_t wcap;
                    uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                    if (wcap >= hlen) {
                        memcpy(out, hdr, hlen);
                        buffer_write_adv(&sess->write_buffer, hlen);
                    }
                }
                state = METP_REQUEST_REPLY;
            }

            else if (cmd && strcmp(cmd, "CHANGE-BUFFER") == 0) {
                char *size_str = strtok_r(NULL, " \r\n", &saveptr);
                if (!size_str) {
                    respuesta_error("400 Bad Request\n", key);
                } else if (!can_user_execute_command(sess->authenticated_user, "CHANGE-BUFFER")) {
                    respuesta_error("403 Forbidden\n", key);
                } else {
                    long new_size = strtol(size_str, NULL, 10);
                    if (new_size <= 0) {
                        respuesta_error("400 Bad Request\n", key);
                    } else {
                        if (!set_io_buffer_size((size_t)new_size)) {
                            respuesta_error("400 Bad Request\n", key);
                        } else if (!resize_metp_buffers(sess, (size_t)new_size)) {
                            respuesta_error("500 Internal Server Error\n", key);
                        } else {
                            respuesta_ok(key);
                        }

                    }
                }
                state = METP_REQUEST_REPLY;
            }
            else if (cmd && strcmp(cmd, "ADD-USER") == 0) {
                char *user = strtok_r(NULL, " \r\n", &saveptr);
                char *pass = strtok_r(NULL, " \r\n", &saveptr);
                if (!user || !pass) {
                    respuesta_error("400 Bad Request\n", key);
                } else if (!can_user_execute_command(sess->authenticated_user, "ADD-USER")) {
                    respuesta_error("403 Forbidden\n", key);
                } else {
                    fprintf(stderr, "[DEBUG] intentando agregar usuario: %s\n", user);
                    fflush(stderr);
                    add_user(user, pass, ROLE_USER);
                    respuesta_ok(key);
                }
                state = METP_REQUEST_REPLY;
            }
            else if (cmd && strcmp(cmd, "DELETE-USER") == 0) {
                char *user = strtok_r(NULL, " \r\n", &saveptr);
                if (!user) {
                    respuesta_error("400 Bad Request\n", key);
                } else if (!can_user_execute_command(sess->authenticated_user, "DELETE-USER")) {
                    respuesta_error("403 Forbidden\n", key);
                } else {
                    remove_user(user);
                    respuesta_ok(key);
                }
                state = METP_REQUEST_REPLY;
            }
            else if (cmd && strcmp(cmd, "SET-ROLE") == 0) {
                char *user = strtok_r(NULL, " \r\n", &saveptr);
                char *role = strtok_r(NULL, " \r\n", &saveptr);
                if (!user || !role) {
                    respuesta_error("400 Bad Request\n", key);
                } else if (!can_user_execute_command(sess->authenticated_user, "SET-ROLE")) {
                    respuesta_error("403 Forbidden\n", key);
                } else if (!set_user_role(user, user_role_from_string(role))) {
                    respuesta_error("400 Bad Request\n", key);
                } else {
                    respuesta_ok(key);
                }
                state = METP_REQUEST_REPLY;
            }
            //TODO: agregar manejo de error
            else if (cmd && strcmp(cmd, "USERS") == 0) {
                if (!can_user_execute_command(sess->authenticated_user, "USERS")) {
                    respuesta_error("403 Forbidden\n", key);
                    state = METP_REQUEST_REPLY;
                } else {
                    const char *list = get_users();
                    respuesta_ok(key);
                    if (*list) {
                        size_t cap;
                        uint8_t *out = buffer_write_ptr(&sess->write_buffer, &cap);
                        size_t len = strlen(list);
                        if (len > cap) len = cap;
                        memcpy(out, list, len);
                        buffer_write_adv(&sess->write_buffer, len);
                    }
                    {
                        const char *dot = ".\n";
                        size_t cap;
                        uint8_t *out = buffer_write_ptr(&sess->write_buffer, &cap);
                        size_t len = 2;
                        if (len > cap) len = cap;
                        memcpy(out, dot, len);
                        buffer_write_adv(&sess->write_buffer, len);
                    }
                    state = METP_REQUEST_REPLY;
                }
                selector_set_interest_key(key, OP_WRITE);
            }

            else if (cmd && strcmp(cmd, "QUIT") == 0) {
                fprintf(stderr, "[DEBUG] comando QUIT detectado\n");
                const char *hdr = "200 OK. Closing conection.\n";
                size_t wcap; 
                uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                size_t hlen = strlen(hdr);
                if (hlen > wcap) hlen = wcap;
                memcpy(out, hdr, hlen);
                buffer_write_adv(&sess->write_buffer, hlen);

                sess->must_close = true;
                state = METP_REQUEST_REPLY;
            }
            else {
                const char *err = "400 Bad Request\n";
                size_t wcap; 
                uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                size_t len = strlen(err);
                if (len > wcap) len = wcap;
                memcpy(out, err, len);
                buffer_write_adv(&sess->write_buffer, len);

                state = METP_REQUEST_REPLY;
            }

            sess->parsers.request.idx = 0;
            break;
        }
    }
    if (state == METP_REQUEST_REPLY || state == METP_ERROR) {
        selector_set_interest_key(key, OP_WRITE);
    }

    selector_set_interest_key(key, OP_WRITE);
    fprintf(stderr, "[DEBUG] selector_set_interest_key(OP_WRITE) ejecutado para QUIT\n");

    return state;
}
static unsigned on_request_write(struct selector_key *key) {
    metp_session *sess = key->data;
    fprintf(stderr, "[DEBUG] entra en on_request_write (sock=%d)\n", sess->sockfd);
    fprintf(stderr, "[DEBUG] must_close = %s, can_read = %s (sock=%d)\n",
        sess->must_close ? "true" : "false",
        buffer_can_read(&sess->write_buffer) ? "yes" : "no",
        sess->sockfd);
    fflush(stderr);

    size_t count;
    uint8_t *out = buffer_read_ptr(&sess->write_buffer, &count);
    if (count > 0) {
        fprintf(stderr, "[DEBUG] on_request_write por QUIT: intentando enviar %zu bytes\n", count);
        ssize_t w = send(sess->sockfd, out, count, 0);
        fprintf(stderr, "[DEBUG] enviados %zd bytes\n", w);
        if (w <= 0) {
            if (w < 0) perror("send() en on_request_write");
            return METP_ERROR;
        }
        buffer_read_adv(&sess->write_buffer, w);
    }

    if (sess->sending_data && !buffer_can_read(&sess->write_buffer)) {
        size_t wcap;
        uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
        size_t to_send = sess->send_remaining;

        if (to_send > wcap) {
            to_send = wcap;
        }

        if (to_send > 0) {
            memcpy(out, sess->send_ptr, to_send);
            buffer_write_adv(&sess->write_buffer, to_send);
            sess->send_ptr += to_send;
            sess->send_remaining -= to_send;
        }

        if (sess->send_remaining == 0) {
            const char *dot = ".\n";
            size_t dlen = strlen(dot);
            out = buffer_write_ptr(&sess->write_buffer, &wcap);
            if (wcap >= dlen) {
                memcpy(out, dot, dlen);
                buffer_write_adv(&sess->write_buffer, dlen);
                sess->sending_data = false;
            }
        }

        selector_set_interest_key(key, OP_WRITE);
        return METP_REQUEST_REPLY;
    }



    if (sess->must_close && !buffer_can_read(&sess->write_buffer)) {
        fprintf(stderr, "[DEBUG] cerrando conexión por QUIT\n");

        struct selector_key sk = *key;  // copiamos el key por si key->data desaparece
        selector_unregister_fd(sk.s, sk.fd);
        close(sk.fd);
        fprintf(stderr, "[DEBUG] liberando sess (sock=%d)\n", sk.fd);

        return METP_DONE;
    }

    if (!buffer_can_read(&sess->write_buffer)) {
        selector_set_interest_key(key, OP_READ);
        return METP_REQUEST;
    }

    return METP_REQUEST_REPLY;
}

static void on_error_arrival(const unsigned state, struct selector_key *key) {
    fprintf(stderr, "[DEBUG] entra en on_error_arrival\n");
    fflush(stderr);
    metp_session *sess = key->data;
    if (!buffer_can_read(&sess->write_buffer)) {
        respuesta_error("500 Internal Server Error\n", key);
    }
    selector_set_interest_key(key, OP_WRITE);
}

static unsigned on_error_write(struct selector_key *key) {
    metp_session *sess = key->data;
    fprintf(stderr, "[DEBUG] entra en on_error_write (sock=%d)\n", sess->sockfd);
    fflush(stderr);
    size_t count;
    uint8_t *out = buffer_read_ptr(&sess->write_buffer, &count);
    if (count > 0) send(sess->sockfd, out, count, 0);
    selector_unregister_fd(key->s, sess->sockfd);
    close(sess->sockfd);
    //falta el free pero creo que aborta si lo agrego
    return METP_DONE;
}

bool set_io_buffer_size(size_t size) {
    if (size == 0 || size > MAX_BUFFER_SIZE)
        return false;
    io_buffer_size = size;
    return true;
}

size_t get_io_buffer_size(void) {
    return io_buffer_size;
}

bool resize_metp_buffers(metp_session *s, size_t new_size) {
    if (!s || new_size == 0 || new_size > MAX_BUFFER_SIZE) {
        return false;
    }

    size_t read_len, write_len;
    uint8_t *read_data  = buffer_read_ptr(&s->read_buffer, &read_len);
    uint8_t *write_data = buffer_read_ptr(&s->write_buffer, &write_len);

    uint8_t *new_read  = malloc(new_size);
    uint8_t *new_write = malloc(new_size);
    if (!new_read || !new_write) {
        free(new_read); free(new_write);
        return false;
    }

    buffer new_rbuf, new_wbuf;
    buffer_init(&new_rbuf, new_size, new_read);
    buffer_init(&new_wbuf, new_size, new_write);

    for (size_t i = 0; i < read_len && buffer_can_write(&new_rbuf); i++)
        buffer_write(&new_rbuf, read_data[i]);

    for (size_t i = 0; i < write_len && buffer_can_write(&new_wbuf); i++)
        buffer_write(&new_wbuf, write_data[i]);

    free(s->raw_read_buffer);
    free(s->raw_write_buffer);
    s->raw_read_buffer = new_read;
    s->raw_write_buffer = new_write;
    s->read_buffer = new_rbuf;
    s->write_buffer = new_wbuf;
    s->buffer_size = new_size;

    return true;
}
