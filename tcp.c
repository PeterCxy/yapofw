#include "tcp.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>

tcp_sock_listen_t *listen_sockets = NULL;
size_t listen_sockets_len = 0;

int tcp_init_from_config(config_item_t *config, size_t config_len) {
    // We always over-allocate to the total number of config lines
    // it should be fine as we don't expect too many lines of configuration
    listen_sockets = malloc(sizeof(tcp_sock_listen_t) * config_len);
    if (listen_sockets == NULL) return -1;

    for (size_t i = 0; i < config_len; i++) {
        if (config[i].src_proto != TCP || config[i].dst_proto != TCP)
            continue;
        // Create listening socket
        int fd = socket(config[i].src_addr.af, SOCK_STREAM, 0);
        if (fd < 0) {
            printf("Cannot create TCP socket\n");
            return -1;
        }

        char *address_str = config_addr_to_str(&config[i].src_addr);
        printf("[TCP] Listening on %s:%d\n", address_str, config[i].src_addr.port);

        size_t sockaddr_len;
        struct sockaddr *address =
            config_addr_to_sockaddr(&config[i].src_addr, &sockaddr_len);
        if (address == NULL) {
            printf("Cannot properly convert TCP socket address\n");
            return -1;
        }

        if (bind(fd, address, sockaddr_len) < 0) {
            printf("Cannot bind to %s:%d\n", address_str, config[i].src_addr.port);
            return -1;
        }

        if (listen(fd, 255) < 0) {
            printf("Cannot listen on %s:%d\n", address_str, config[i].src_addr.port);
            return -1;
        }

        listen_sockets[listen_sockets_len].src_fd = fd;
        listen_sockets[listen_sockets_len].dst_addr = config[i].dst_addr;
        listen_sockets_len++;

        free(address_str);
        free(address);
    }
    
    return 0;
}