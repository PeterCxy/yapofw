#pragma once
#include "config.h"
#include <stdlib.h>
#define STATS_DIRECTION_SRC_DST 0
#define STATS_DIRECTION_DST_SRC 1

typedef struct {
    char listen_addr_key[255];
    unsigned long long bytes_transmitted;
    unsigned long long bytes_received;
} yapofw_stats_t;

int stats_init_from_config(config_item_t *config, size_t config_len, const char *persist_file);
// Record some number of bytes transmitted.
// cfg_idx is the index of the concerning connection in the configuration file
// The CALLER should make sure cfg_idx is always a valid index in the configuration array
void stats_add_bytes(size_t cfg_idx, unsigned long bytes, int direction);