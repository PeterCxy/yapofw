#pragma once
#include "config.h"

typedef struct {
    int src_fd;
    config_addr_t dst_addr;
} tcp_sock_listen_t;

// Handles connections that originate from TCP and destines to a TCP port
int tcp_init_from_config(config_item_t *config, size_t config_len);