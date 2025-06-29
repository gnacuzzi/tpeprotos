#ifndef METRICTS_H
#define METRICS_H

#include <stdint.h>


uint32_t get_historic_connections();
uint32_t get_socks_current_connections();
uint64_t get_bytes_transferred();


#endif
