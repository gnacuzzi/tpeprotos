// echo_client.c
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../utils/include/netutils.h"

#define PORT "1080"

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

int main(int argc, char *argv[]) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int sockfd = create_connection(host, PORT);
    if (sockfd < 0) {
        perror("connect");
        return EXIT_FAILURE;
    }

    // mostramos la dirección remota
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    if (getpeername(sockfd, (struct sockaddr *)&addr, &len) == 0) {
        char hbuf[64];
        printf("Conectado a %s\n",
            sockaddr_to_human(hbuf, sizeof(hbuf), (struct sockaddr *)&addr));
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(sockfd);
        return EXIT_FAILURE;
    }

    if (pid == 0) {
        // Hijo: copia todo lo que venga del socket → stdout
        sock_blocking_copy(sockfd, STDOUT_FILENO);
        _exit(EXIT_SUCCESS);
    } else {
        // Padre: copia stdin → socket (usando read/send en lugar de recv/send)
        ssize_t nread;
        char buf[4096];
        while ((nread = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
            ssize_t to_write = nread;
            char *out_ptr    = buf;
            while (to_write > 0) {
                ssize_t nw = send(sockfd, out_ptr, to_write, MSG_NOSIGNAL);
                if (nw <= 0) {
                    perror("send");
                    goto done;
                }
                to_write -= nw;
                out_ptr   += nw;
            }
        }
        // avisamos al servidor fin de envío para que responda y cierre
        shutdown(sockfd, SHUT_WR);
done:
        wait(NULL);  // esperamos al hijo
    }

    close(sockfd);
    return EXIT_SUCCESS;
}
