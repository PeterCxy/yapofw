#include "tcp.h"
#include "util.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

tcp_sock_listen_t *listen_sockets = NULL;
size_t listen_sockets_len = 0;

int tcp_init_from_config(config_item_t *config, size_t config_len) {
    // We always over-allocate to the total number of config lines
    // it should be fine as we don't expect too many lines of configuration
    listen_sockets = malloc(sizeof(tcp_sock_listen_t) * config_len);
    if (listen_sockets == NULL) return -1;
    bzero(listen_sockets, sizeof(tcp_sock_listen_t) * config_len);

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

        size_t sockaddr_len = 0;
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
        listen_sockets[listen_sockets_len].src_addr = config[i].src_addr;
        listen_sockets[listen_sockets_len].dst_addr = config[i].dst_addr;
        listen_sockets_len++;

        free(address_str);
        free(address);
    }
    
    return 0;
}

int tcp_build_fd_sets(fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    int max_fd = -1;

    // All listening sockets need to be monitored for read
    for (int i = 0; i < listen_sockets_len; i++) {
        FD_SET(listen_sockets[i].src_fd, readfds);
        if (listen_sockets[i].src_fd > max_fd)
            max_fd = listen_sockets[i].src_fd;
    }

    return max_fd;
}

void tcp_handle_accept(fd_set *readfds) {
    char ip_str[255];
    bzero(ip_str, 255);

    // Loop over all listening sockets to see if we need to accept any new connection
    for (int i = 0; i < listen_sockets_len; i++) {
        if (!FD_ISSET(listen_sockets[i].src_fd, readfds)) continue;
        // New connection!
        struct sockaddr client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_fd;
        if ((client_fd = accept(listen_sockets[i].src_fd, &client_addr, &client_addr_len)) < 0) {
            printf("[TCP] Error accepting incoming connection: %s\n", strerror(errno));
            continue;
        }

        printf("[TCP] New connection from %s:%d on %s:%d, target: %s:%d\n",
            get_ip_str(&client_addr, ip_str, 255), get_ip_port(&client_addr),
            config_addr_to_str(&listen_sockets[i].src_addr), listen_sockets[i].src_addr.port,
            config_addr_to_str(&listen_sockets[i].dst_addr), listen_sockets[i].dst_addr.port);
    }
}

void tcp_ev_loop_handler(fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    // Handle new connections from the listening socket
    tcp_handle_accept(readfds);
}