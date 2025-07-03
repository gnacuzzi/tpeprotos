#include "metrics.h"

static uint32_t historic_connections;
static uint32_t socks_current_connections;
static uint64_t bytes_transferred;

void init_metrics(void) {
    historic_connections = 0;
    socks_current_connections = 0;
    bytes_transferred = 0;
}

uint32_t get_historic_connections(void) {
    return historic_connections;
}

uint32_t get_socks_current_connections(void) {
    return socks_current_connections;
}

uint64_t get_bytes_transferred(void) {
    return bytes_transferred;
}

//TODO: ver desde donde llamamos a estas funciones
void increment_historic_connections(void) {
    historic_connections++;
}

void increment_current_connections(void) {
    socks_current_connections++;
}

void decrement_current_connections(void) {
    if (socks_current_connections > 0) {
        socks_current_connections--;
    }
}

void add_bytes_transferred(uint64_t bytes) {
    bytes_transferred += bytes;
}

