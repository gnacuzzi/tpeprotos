#include "include/argsmetp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static char * my_strdup(const char *s) {
    size_t len = strlen(s) + 1;
    char *p = malloc(len);
    if (p) memcpy(p, s, len);
    return p;
}

static void parse_user(const char *s, char *out_user, char *out_pass) {
    char *copy = my_strdup(s);
    if (!copy) {
        perror("strdup");
        exit(EXIT_FAILURE);
    }
    char *sep = strchr(copy, ':');
    if (!sep) {
        fprintf(stderr, "Formato inválido de credencial '%s', falta ':'\n", s);
        free(copy);
        exit(EXIT_FAILURE);
    }
    *sep = '\0';
    sep++;

    snprintf(out_user, MAX_NAME, "%s", copy);
    snprintf(out_pass, MAX_PASS, "%s", sep);

    free(copy);
}


static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "  -h                Imprime esta ayuda y sale\n"
        "  -v                Imprime versión y sale\n"
        "  -p <port>         Puerto del servidor METP (default 8080)\n"
        "  -u <user>:<pass>  Credenciales de autenticación\n"
        "  -g                GET_LOGS\n"
        "  -m                GET_METRICS\n"
        "  -c <size>         CHANGE-BUFFER\n"
        "  -a <user> <pass>  ADD-USER\n"
        "  -d <user>         DELETE-USER\n"
        "  -r <user> <role>  SET-ROLE\n", prog);
}

static void version(void) {
    printf("METP client version 1.0\n");
}

void parsemetp_args(int argc, char **argv, metpargs *args) {
    args->metp_addr = "127.0.0.1";
    args->metp_port = 8080;
    args->auth_user[0] = '\0';
    args->auth_pass[0] = '\0';
    args->nusers = 0;
    args->du_user[0] = '\0';
    args->sr_user[0] = '\0';
    args->sr_role[0] = '\0';
    args->cb_size = 0;
    args->mode = MODE_NONE;

    int opt;
    static struct option long_opts[] = {
        {"help",    no_argument,       0, 'h'},
        {"version", no_argument,       0, 'v'},
        {"port",    required_argument, 0, 'p'},
        {"user",    required_argument, 0, 'u'},
        {"gl",      no_argument,       0, 'g'},
        {"gm",      no_argument,       0, 'm'},
        {"cb",      required_argument, 0, 'c'},
        {"au",      required_argument, 0, 'a'},
        {"du",      required_argument, 0, 'd'},
        {"sr",      required_argument, 0, 'r'},
        {0,0,0,0}
    };
    const char *optstring = "hv:p:u:gmc:a:d:r:";

    while ((opt = getopt_long(argc, argv, optstring, long_opts, NULL)) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            exit(0);
        case 'v':
            version();
            exit(0);
        case 'p':
            args->metp_port = (unsigned short)atoi(optarg);
            break;
        case 'u': {//todo: algo no esta funcionando
            parse_user(optarg,
                    args->auth_user,
                    args->auth_pass);
            break;
        }
        case 'g':
            args->mode = MODE_GET_LOGS;
            break;
        case 'm':
            args->mode = MODE_GET_METRICS;
            break;
        case 'c':
            args->cb_size = strtoull(optarg, NULL, 10);
            args->mode = MODE_CHANGE_BUFFER;
            break;
        case 'a': {
            if (optind >= argc) {
                fprintf(stderr, "-a requiere user y pass\n");
                usage(argv[0]);
            }
            strncpy(args->users[args->nusers].name, optarg, MAX_NAME - 1);
            strncpy(args->users[args->nusers].pass, argv[optind++], MAX_PASS - 1);
            args->nusers++;
            args->mode = MODE_ADD_USER;
            break;
        }
        case 'd':
            strncpy(args->du_user, optarg, MAX_NAME - 1);
            args->mode = MODE_DELETE_USER;
            break;
        case 'r': {
            if (optind >= argc) {
                fprintf(stderr, "-r requiere user y role\n");
                usage(argv[0]);
            }
            strncpy(args->sr_user, optarg, MAX_NAME - 1);
            strncpy(args->sr_role, argv[optind++], MAX_ROLE - 1);
            args->mode = MODE_SET_ROLE;
            break;
        }
        default:
            usage(argv[0]);
        }
    }

    if (args->mode == MODE_NONE) {
        fprintf(stderr, "Ningún comando especificado\n");
        usage(argv[0]);
        exit(1);
    }
}
