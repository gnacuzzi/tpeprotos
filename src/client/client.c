// echo_client_sync.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>

#define BUF_SIZE 4096
#define PORT      "1080"

static int create_connection(const char *host, const char *port);

int main(int argc, char *argv[]) {
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    int sockfd = create_connection(host, PORT);
    if (sockfd < 0) {
        perror("connect");
        return EXIT_FAILURE;
    }

    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), stdin)) {
        size_t to_send = strlen(line);
        ssize_t sent = send(sockfd, line, to_send, 0);
        if (sent <= 0) {
            perror("send");
            break;
        }

        size_t total_recv = 0;
        while (total_recv < (size_t)sent) {
            ssize_t rec = recv(sockfd,
                               line + total_recv,
                               sent - total_recv,
                               0);
            if (rec < 0) {
                perror("recv");
                goto done;
            }
            if (rec == 0) {
                fprintf(stderr, "server closed connection early\n");
                goto done;
            }
            total_recv += rec;
        }

        line[total_recv] = '\0';
        fputs(line, stdout);
    }

done:
    close(sockfd);
    return EXIT_SUCCESS;
}

static int create_connection(const char *host, const char *port) {
    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
    }, *res, *rp;
    int sockfd;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    for (rp = res; rp; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) continue;
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sockfd);
    }
    freeaddrinfo(res);
    return rp ? sockfd : -1;
}
