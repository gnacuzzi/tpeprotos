#ifndef METRICTS_H
#define METRICTS_H

#include <stdint.h>

void init_metrics(void);
uint32_t get_historic_connections(void);
uint32_t get_socks_current_connections(void);
uint64_t get_bytes_transferred(void);

void increment_historic_connections(void);
void increment_current_connections(void);
void decrement_current_connections(void);
void add_bytes_transferred(uint64_t bytes);

#endif
