#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>

void init_metrics();
uint32_t get_historic_connections();
uint32_t get_socks_current_connections();
uint64_t get_bytes_transferred();

void increment_historic_connections();
void increment_current_connections();
void decrement_current_connections();
void add_bytes_transferred(uint64_t bytes);

#endif
