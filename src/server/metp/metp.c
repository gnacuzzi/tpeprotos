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
        fprintf(stderr, "[DEBUG] recv <= 0, estado -> METP_ERROR\n");
        fflush(stderr);
        return METP_ERROR;
    }
    buffer_write_adv(&sess->read_buffer, n);

    uint8_t c;
    while (buffer_can_read(&sess->read_buffer)) {
        c = buffer_read(&sess->read_buffer);

        if (sess->parsers.auth.idx < BUFFER_SIZE - 1) {
            sess->parsers.auth.line[sess->parsers.auth.idx++] = (char)c;
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
    unsigned state = METP_ERROR; 
    
    uint8_t *in = buffer_write_ptr(&sess->read_buffer, &cap);
    ssize_t n = recv(sess->sockfd, in, cap, 0);
    if (n <= 0) {
        return METP_ERROR;
    }
    buffer_write_adv(&sess->read_buffer, n);

    uint8_t c;
    while (buffer_can_read(&sess->read_buffer)) {
        c = buffer_read(&sess->read_buffer);
        if (sess->parsers.auth.idx < BUFFER_SIZE - 1) {
            sess->parsers.auth.line[sess->parsers.auth.idx++] = (char)c;
        }

        if (c == '\n' || sess->parsers.auth.idx == BUFFER_SIZE - 1) {
            sess->parsers.auth.line[sess->parsers.auth.idx] = '\0';

            char *saveptr = NULL;
            char *cmd = strtok_r(sess->parsers.auth.line, " \r\n", &saveptr);
            if (cmd && strcmp(cmd, "AUTH") == 0) {
                char *user = strtok_r(NULL, " \r\n", &saveptr);
                char *pass = strtok_r(NULL, " \r\n", &saveptr);
                bool ok = verify_user(user, pass);

                const char *resp = ok
                    ? "200 OK\n"
                    : "401 Unauthorized\n";
                size_t wcap;
                uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                size_t len = strlen(resp);
                if (len > wcap) len = wcap;
                memcpy(out, resp, len);
                buffer_write_adv(&sess->write_buffer, len);

                if (ok) {
                    sess->is_authenticated = true;
                    strncpy(sess->authenticated_user, user, MAX_USERNAME_LEN - 1);
                    sess->authenticated_user[MAX_USERNAME_LEN - 1] = '\0';
                    state = METP_AUTH_REPLY;
                } else {
                    state = METP_AUTH_REPLY;
                }
            } else {
                const char *resp = "400 Bad Request\n";
                size_t wcap;
                uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                size_t len = strlen(resp);
                if (len > wcap) len = wcap;
                memcpy(out, resp, len);
                buffer_write_adv(&sess->write_buffer, len);

                state = METP_ERROR;
            }

            sess->parsers.auth.idx = 0;
            break;
        }
    }
    if (state == METP_AUTH_REPLY || state == METP_ERROR) {
        selector_set_interest_key(key, OP_WRITE);
    }
    return state;
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


static unsigned on_request_read(struct selector_key *key) {
    metp_session *sess = key->data;
    fprintf(stderr, "[DEBUG] entra en on_request_read (sock=%d)\n", sess->sockfd);
    fflush(stderr);
    size_t cap;
    unsigned state = METP_ERROR;

    uint8_t *in = buffer_write_ptr(&sess->read_buffer, &cap);
    ssize_t n = recv(sess->sockfd, in, cap, 0);
    if (n <= 0) return METP_ERROR;
    buffer_write_adv(&sess->read_buffer, n);

    uint8_t c;
    while (buffer_can_read(&sess->read_buffer)) {
        c = buffer_read(&sess->read_buffer);
        if (sess->parsers.request.idx < BUFFER_SIZE - 1) {
            sess->parsers.request.line[sess->parsers.request.idx++] = (char)c;
        }
        if (c == '\n' || sess->parsers.request.idx == BUFFER_SIZE - 1) {
            sess->parsers.request.line[sess->parsers.request.idx] = '\0';

            char *saveptr = NULL;
            char *cmd = strtok_r(sess->parsers.request.line, " \r\n", &saveptr);

            if (cmd && strcmp(cmd, "GET_METRICS") == 0) {
                // todo: ver bien si queremos que todos tengan acceso
                if (!can_user_execute_command(sess->authenticated_user, "GET_METRICS")) {
                    const char *err = "403 Forbidden\n";
                    size_t wcap; 
                    uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                    size_t len = strlen(err);
                    if (len > wcap) len = wcap;
                    memcpy(out, err, len);
                    buffer_write_adv(&sess->write_buffer, len);
                    state = METP_ERROR;
                } else {
                    char tmp[128];
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

                    size_t wcap; 
                    uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                    if ((size_t)len > wcap) len = wcap;
                    memcpy(out, tmp, len);
                    buffer_write_adv(&sess->write_buffer, len);

                    state = METP_REQUEST_REPLY;
                }
            }
            else if (cmd && strcmp(cmd, "GET_LOGS") == 0) {
                if (!can_user_execute_command(sess->authenticated_user, "GET_LOGS")) {
                    const char *err = "403 Forbidden\n";
                    size_t wcap; 
                    uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                    size_t len = strlen(err);
                    if (len > wcap) len = wcap;
                    memcpy(out, err, len);
                    buffer_write_adv(&sess->write_buffer, len);
                    state = METP_ERROR;
                } else {
                    const char *hdr = "200 OK\n";
                    size_t wcap; 
                    uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                    size_t hlen = strlen(hdr);
                    if (hlen > wcap) hlen = wcap;
                    memcpy(out, hdr, hlen);
                    buffer_write_adv(&sess->write_buffer, hlen);

                    const char *logs_data = get_logs();
                    if (logs_data && strlen(logs_data) > 0) {
                        out = buffer_write_ptr(&sess->write_buffer, &wcap);
                        size_t logs_len = strlen(logs_data);
                        if (logs_len > wcap) logs_len = wcap;
                        memcpy(out, logs_data, logs_len);
                        buffer_write_adv(&sess->write_buffer, logs_len);
                    }

                    const char *dot = ".\n";
                    out = buffer_write_ptr(&sess->write_buffer, &wcap);
                    size_t dlen = strlen(dot);
                    if (dlen > wcap) dlen = wcap;
                    memcpy(out, dot, dlen);
                    buffer_write_adv(&sess->write_buffer, dlen);

                    state = METP_REQUEST_REPLY;
                }
            }
            else if (cmd && strcmp(cmd, "POST_CONFIG") == 0) {
                if (!can_user_execute_command(sess->authenticated_user, "POST_CONFIG")) {
                    const char *err = "403 Forbidden\n";
                    size_t wcap; 
                    uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                    size_t len = strlen(err);
                    if (len > wcap) len = wcap;
                    memcpy(out, err, len);
                    buffer_write_adv(&sess->write_buffer, len);
                    state = METP_ERROR;
                } else {
                    static char config_buffer[4096];
                    static size_t config_pos = 0;
                    
                    config_pos = 0;
                    config_buffer[0] = '\0';
                    
                    while (buffer_can_read(&sess->read_buffer)) {
                        c = buffer_read(&sess->read_buffer);
                        
                        if (config_pos < sizeof(config_buffer) - 1) {
                            config_buffer[config_pos++] = (char)c;
                        }
                        
                        if (c == '\n') {
                            config_buffer[config_pos] = '\0';
                            
                            char *line_end = strrchr(config_buffer, '\n');
                            if (line_end) {
                                *line_end = '\0';
                                if (strcmp(config_buffer, ".") == 0) {
                                    break;
                                }
                                *line_end = '\n'; 
                            }
                        }
                    }
                    
                    bool config_ok = apply_configuration(config_buffer);
                    
                    const char *resp = config_ok ? "200 OK\n" : "400 Bad Request\n";
                    size_t wcap; 
                    uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                    size_t len = strlen(resp);
                    if (len > wcap) len = wcap;
                    memcpy(out, resp, len);
                    buffer_write_adv(&sess->write_buffer, len);

                    state = METP_REQUEST_REPLY;
                }
            }
            else {
                const char *err = "400 Bad Request\n";
                size_t wcap; 
                uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                size_t len = strlen(err);
                if (len > wcap) len = wcap;
                memcpy(out, err, len);
                buffer_write_adv(&sess->write_buffer, len);

                state = METP_ERROR;
            }

            sess->parsers.request.idx = 0;
            break;
        }
    }

    return state;
}

static unsigned on_request_write(struct selector_key *key) {
    metp_session *sess = key->data;
    fprintf(stderr, "[DEBUG] entra en on_request_write (sock=%d)\n", sess->sockfd);
    fflush(stderr);
    size_t count;

    uint8_t *out = buffer_read_ptr(&sess->write_buffer, &count);
    ssize_t w = send(sess->sockfd, out, count, 0);
    if (w <= 0) {
        return METP_ERROR;
    }

    buffer_read_adv(&sess->write_buffer, w);

    if (!buffer_can_read(&sess->write_buffer)) {
        selector_set_interest_key(key, OP_READ);
        return METP_REQUEST;
    }

    return METP_REQUEST_REPLY;
}

static void on_error_arrival(const unsigned state, struct selector_key *key) {
    fprintf(stderr, "[DEBUG] entra en on_error_arrival\n");
    fflush(stderr);
    selector_set_interest_key(key, OP_WRITE);
}

static unsigned on_error_write(struct selector_key *key) {
    metp_session *sess = key->data;
    fprintf(stderr, "[DEBUG] entra en on_error_write (sock=%d)\n", sess->sockfd);
    fflush(stderr);
    size_t count;
    uint8_t *out = buffer_read_ptr(&sess->write_buffer, &count);
    if (count > 0) send(sess->sockfd, out, count, 0);
    close(sess->sockfd);
    return METP_DONE;
}


