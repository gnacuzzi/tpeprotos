#include "include/socks5.h"
#include <stdlib.h>

static void on_greet(const unsigned state, struct selector_key *key);
static unsigned on_greet_read   (struct selector_key *key);
static unsigned on_greet_write  (struct selector_key *key);

static const struct state_definition socks5_states[] = {
    [SOCKS5_GREETING] = {
        .state          = SOCKS5_GREETING,
        .on_arrival     = on_greet,
        .on_read_ready  = on_greet_read,
    },
    [SOCKS5_GREETING_REPLY] = {
        .state          = SOCKS5_GREETING_REPLY,
        .on_write_ready = on_greet_write,
    },
};

const struct state_definition *get_socks5_states(void) {
  return socks5_states;
}


//faltan un monton de cosas
static void on_greet(const unsigned state, struct selector_key *key) {
    socks5_session *s = key->data;
    //seguro falta algo
}

static unsigned on_greet_read(struct selector_key *key) {
    socks5_session *s = key->data;
    return SOCKS5_GREETING_REPLY;
}

static unsigned on_greet_write(struct selector_key *key) {
    socks5_session *s = key->data;
    return SOCKS5_REQUEST;
}


