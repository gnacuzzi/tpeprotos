#include "metrics.h"

static uint32_t historic_connections;
static uint32_t socks_current_connections;
static uint64_t bytes_transferred;

void init_metrics() {
    historic_connections = 0;
    socks_current_connections = 0;
    bytes_transferred = 0;
}

uint32_t get_historic_connections() {
    return historic_connections;
}

uint32_t get_socks_current_connections() {
    return socks_current_connections;
}

uint64_t get_bytes_transferred() {
    return bytes_transferred;
}

void increment_historic_connections() {
    historic_connections++;
}

void increment_current_connections() {
    socks_current_connections++;
}

void decrement_current_connections() {
    if (socks_current_connections > 0) {
        socks_current_connections--;
    }
}

//TODO: usar en stream
void add_bytes_transferred(uint64_t bytes) {
    bytes_transferred += bytes;
}

