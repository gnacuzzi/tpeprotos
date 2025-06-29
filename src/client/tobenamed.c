#include "include/metp.h"

int sockfd = -1; 
bool is_connected = false; 

static ssize_t send_full(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t w = send(fd, buf + sent, len - sent, 0);
        if (w < 0) return -1;       
        sent += w;
    }
    return sent;
}

static ssize_t recv_line(int fd, char *out, size_t maxlen) {
    size_t pos = 0;
    while (pos + 1 < maxlen) {
        char c;
        ssize_t r = recv(fd, &c, 1, 0);
        if (r <= 0) return -1;     
        out[pos++] = c;
        if (c == '\n') break;
    }
    out[pos] = '\0';
    return pos;
}

static char * my_strdup(const char *s) {
    size_t len = strlen(s) + 1;
    char *p = malloc(len);
    if (p) memcpy(p, s, len);
    return p;
}



pc_connect_status proxy_connect(const char *host, unsigned short port, const proxy_user *user) {
    if (is_connected) return PC_SERV_FAIL;

    struct addrinfo hints = {0}, *res, *p;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char portstr[6];
    snprintf(portstr, sizeof(portstr), "%u", port);

    int status = getaddrinfo(host, portstr, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return PC_SERV_FAIL;
    }

    for (p = res; p; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0) continue;
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == 0) {
            is_connected = true;
            break;
        }
        close(sockfd);
    }
    freeaddrinfo(res);
    if (!is_connected) return PC_SERV_FAIL;

    char buf[BUFFER_SIZE];
    send_full(sockfd, "HELLO METP/1.0\n", 21);
    if (recv_line(sockfd, buf, sizeof(buf)) <= 0 ||
        strncmp(buf, "200 ", 4) != 0)
        return PC_SERV_FAIL;

    snprintf(buf, sizeof(buf), "AUTH %s %s\n", user->name, user->pass);
    send_full(sockfd, buf, strlen(buf));
    if (recv_line(sockfd, buf, sizeof(buf)) <= 0 ||
        strncmp(buf, "200 ", 4) != 0)
        return PC_AUTH_FAIL;

    return PC_SUCCESS;
}

void proxy_close(void) {
    if (sockfd != -1) {
        close(sockfd);
        sockfd = -1;
        is_connected = false;
    }
}


static pc_response_status do_post_config(const char *body) {
    char line[BUFFER_SIZE];
    if (send_full(sockfd, "POST_CONFIG\n", 12) <= 0) 
        return PC_RES_SERV_FAIL;

    if (send_full(sockfd, body, strlen(body)) <= 0) 
        return PC_RES_SERV_FAIL;

    if (send_full(sockfd, ".\n", 2) <= 0) 
        return PC_RES_SERV_FAIL;

    if (recv_line(sockfd, line, sizeof(line)) <= 0) 
        return PC_RES_SERV_FAIL;

    if (strncmp(line, "200", 3) == 0)      return PC_RES_SUCCESS;
    if (strncmp(line, "400", 3) == 0)      return PC_RES_CMD_FAIL;
    if (strncmp(line, "403", 3) == 0)      return PC_RES_NOT_AUTHORIZED;
    return PC_RES_SERV_FAIL;
}


pc_response_status proxy_set_max_io_buffer(uint64_t bytes) {
    if (!is_connected) return PC_RES_SERV_FAIL;
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "max_io_buffer=%llu\n", (unsigned long long)bytes);
    if (n < 0 || n >= sizeof(buf)) return PC_RES_CMD_FAIL; 
    return do_post_config(buf);
}

pc_response_status proxy_add_user(const proxy_user *u) {
    if (!is_connected) return PC_RES_SERV_FAIL;
    char buf[128];
    int n = snprintf(buf, sizeof(buf), "add_user=%s:%s\n", u->name, u->pass);
    if (n < 0 || n >= sizeof(buf)) return PC_RES_CMD_FAIL;
    return do_post_config(buf);
}

pc_response_status proxy_remove_user(const char *username) {
    if (!is_connected) return PC_RES_SERV_FAIL;
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "remove_user=%s\n", username);
    if (n < 0 || n >= sizeof(buf)) return PC_RES_CMD_FAIL;
    return do_post_config(buf);
}

pc_response_status proxy_set_role(const char *username, const char *role) {
    if (!is_connected) return PC_RES_SERV_FAIL;
    char buf[128];
    int n = snprintf(buf, sizeof(buf), "set_role=%s:%s\n", username, role);
    if (n < 0 || n >= sizeof(buf)) return PC_RES_CMD_FAIL;
    return do_post_config(buf);
}

pc_response_status proxy_get_metrics(proxy_metrics *m) {
    if (!is_connected) return PC_RES_SERV_FAIL;
    char line[BUFFER_SIZE];

    if (send_full(sockfd, "GET_METRICS\n", 12) <= 0)
        return PC_RES_SERV_FAIL;

    if (recv_line(sockfd, line, sizeof(line)) <= 0 ||
        strncmp(line, "200", 3) != 0)
        return PC_RES_CMD_FAIL;

    while (recv_line(sockfd, line, sizeof(line)) > 0) {
        if (strcmp(line, ".\n") == 0) break;
        if (strncmp(line, "HISTORICAL_CONNECTIONS:", 24) == 0)
            m->historical_connections = strtoull(line + 24, NULL, 10);
        else if (strncmp(line, "CURRENT_CONNECTIONS:", 20) == 0)
            m->current_connections = strtoull(line + 20, NULL, 10);
        else if (strncmp(line, "BYTES_TRANSFERRED:", 18) == 0)
            m->bytes_transferred = strtoull(line + 18, NULL, 10);
    }
    return PC_RES_SUCCESS;
}

pc_response_status proxy_get_logs(proxy_log_list *L) {
    if (!is_connected) return PC_RES_SERV_FAIL;
    char line[BUFFER_SIZE];

    if (send_full(sockfd, "GET_LOGS\n", 9) <= 0)
        return PC_RES_SERV_FAIL;

    if (recv_line(sockfd, line, sizeof(line)) <= 0 ||
        strncmp(line, "200", 3) != 0)
        return PC_RES_CMD_FAIL;

    size_t cap = 16, cnt = 0;
    L->entries = malloc(cap * sizeof(*L->entries));
    L->count   = 0;

    while (recv_line(sockfd, line, sizeof(line)) > 0) {
        if (strcmp(line, ".\n") == 0) break;
        char ts[64], user[64], ip[64], dest[64];
        unsigned long long bytes;
        if (sscanf(line, "[%63[^]]] %63s %63s %63s %llu", ts, user, ip, dest, &bytes) == 5) {
            if (cnt >= cap) {
                cap *= 2;
                L->entries = realloc(L->entries, cap * sizeof(*L->entries));
            }
            proxy_log_entry *e = &L->entries[cnt++];
            e->timestamp     = my_strdup(ts);
            e->user          = my_strdup(user);
            e->ip_src        = my_strdup(ip);
            e->dest          = my_strdup(dest);
            e->bytes         = bytes;
        }
    }
    L->count = cnt;
    return PC_RES_SUCCESS;
}

void free_proxy_log_list(proxy_log_list *L) {
    for (size_t i = 0; i < L->count; i++) {
        free(L->entries[i].timestamp);
        free(L->entries[i].user);
        free(L->entries[i].ip_src);
        free(L->entries[i].dest);
    }
    free(L->entries);
}

//TODO: cambiar a ingles?
const char* pc_connect_status_to_string(pc_connect_status status) {
    switch (status) {
        case PC_SUCCESS:     return "Conexión exitosa";
        case PC_SERV_FAIL:   return "Fallo del servidor al conectar";
        case PC_AUTH_FAIL:   return "Fallo de autenticación";
        default:             return "Estado de conexión desconocido";
    }
}

const char* pc_response_status_to_string(pc_response_status status) {
    switch (status) {
        case PC_RES_SUCCESS:          return "Operación exitosa";
        case PC_RES_SERV_FAIL:        return "Fallo del servidor en la operación";
        case PC_RES_CMD_FAIL:         return "Comando inválido o mal formado";
        case PC_RES_NOT_AUTHORIZED:   return "No autorizado para ejecutar el comando";
        default:                      return "Respuesta desconocida";
    }
}

