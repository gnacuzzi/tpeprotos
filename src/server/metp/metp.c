#include "metp.h"

static unsigned on_hello_read(struct selector_key *key);
static unsigned on_hello_write(struct selector_key *key);
static unsigned on_authentication_read(struct selector_key *key);
static unsigned on_authentication_write(struct selector_key *key);
static void on_request(const unsigned state, struct selector_key *key);
static unsigned on_request_read(struct selector_key *key);
static unsigned on_request_write(struct selector_key *key);

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
    [METP_DONE] = {
        .state          = METP_DONE,
    },
    [METP_ERROR] = {
        .state          = METP_ERROR,
    }
};

const struct state_definition *get_metp_states(void) {
  return metp_states;
}

static unsigned on_hello_read(struct selector_key *key) {
    metp_session *sess = key->data;
    size_t cap;
    unsigned state = METP_ERROR;  

    uint8_t *in = buffer_write_ptr(&sess->read_buffer, &cap);
    ssize_t n = recv(sess->sockfd, in, cap, 0);
    if (n <= 0) return METP_ERROR;
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
                const char *resp = "200 Welcome to " METP_VERSION "\n";

                size_t wcap;
                uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                size_t len = strlen(resp);
                if (len > wcap) len = wcap;
                memcpy(out, resp, len);
                buffer_write_adv(&sess->write_buffer, len);

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
            }

            sess->parsers.auth.idx = 0;
            break;
        }
    }

    return state;
}


static unsigned on_hello_write(struct selector_key *key) {
    metp_session *sess = key->data;
    size_t count;
    uint8_t *out = buffer_read_ptr(&sess->write_buffer, &count);
    ssize_t w = send(sess->sockfd, out, count, 0);
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
                bool ok = false; //TODO: VERIFY_USER (user && pass && verify_user(user, pass));

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

    return state;
}

static unsigned on_authentication_write(struct selector_key *key) {
    metp_session *sess = key->data;
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
            else if (cmd && strcmp(cmd, "GET_LOGS") == 0) {
                const char *hdr = "200 OK\n";
                size_t wcap; 
                uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                size_t hlen = strlen(hdr);
                if (hlen > wcap) hlen = wcap;
                memcpy(out, hdr, hlen);
                buffer_write_adv(&sess->write_buffer, hlen);

                //TODO: Implement GET_LOGS handler

                const char *dot = ".\n";
                out = buffer_write_ptr(&sess->write_buffer, &wcap);
                size_t dlen = strlen(dot);
                if (dlen > wcap) dlen = wcap;
                memcpy(out, dot, dlen);
                buffer_write_adv(&sess->write_buffer, dlen);

                state = METP_REQUEST_REPLY;
            }
            else if (cmd && strcmp(cmd, "POST_CONFIG") == 0) {
                
                //TODO: Implement POST_CONFIG handler

                const char *resp = "200 OK\n";
                size_t wcap; 
                uint8_t *out = buffer_write_ptr(&sess->write_buffer, &wcap);
                size_t len = strlen(resp);
                if (len > wcap) len = wcap;
                memcpy(out, resp, len);
                buffer_write_adv(&sess->write_buffer, len);

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


