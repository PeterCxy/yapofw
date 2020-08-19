#include "stats.h"
#include <stdio.h>
#include <string.h>

yapofw_stats_t *stats;
size_t stats_len = 0;

int stats_init_from_config(config_item_t *config, size_t config_len) {
    // Initialize the stats array
    stats = malloc(config_len * sizeof(yapofw_stats_t));
    if (stats == NULL) {
        return -1;
    }
    memset(stats, 0, config_len * sizeof(yapofw_stats_t));
    stats_len = config_len;

    char ip_str[255];
    for (int i = 0; i < config_len; i++) {
        config_addr_to_str(&config[i].src_addr, ip_str, 255);
        sprintf(stats[i].listen_addr_key, "%s:%d", ip_str, config[i].src_addr.port);
    }

    // TODO: load from persistent storage
    return 0;
}

void stats_add_bytes(size_t cfg_idx, unsigned long bytes, int direction) {
    if (direction == STATS_DIRECTION_SRC_DST) {
        stats[cfg_idx].bytes_transmitted += bytes;
    } else if (direction == STATS_DIRECTION_DST_SRC) {
        stats[cfg_idx].bytes_received += bytes;
    }
}