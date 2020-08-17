#pragma once
#include "config.h"
#include <sys/select.h>

typedef struct {
    int src_fd;
    config_addr_t src_addr;
    config_addr_t dst_addr;
} tcp_sock_listen_t;

// Handles connections that originate from TCP and destines to a TCP port
int tcp_init_from_config(config_item_t *config, size_t config_len);
// Builds fd sets that the TCP module concerns about
// returns the maximum fd as found in this module,
// -1 if none
int tcp_build_fd_sets(fd_set *readfds, fd_set *writefds, fd_set *exceptfds);
// The event loop handler for the TCP module
void tcp_ev_loop_handler(fd_set *readfds, fd_set *writefds, fd_set *exceptfds);