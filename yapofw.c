#include "config.h"
#include "tcp.h"
#include <stdio.h>
#include <sys/select.h>

void ev_loop() {
    fd_set readfds, writefds, exceptfds;
    int nfds = 0;
    int select_res = 0;

    do {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_ZERO(&exceptfds);

        // Build fd sets
        int nfds_tcp = tcp_build_fd_sets(&readfds, &writefds, &exceptfds);
        if (nfds_tcp > nfds) {
            nfds = nfds_tcp;
        }

        // nfds is the max fd + 1
        nfds++;
        
        // Skip if no fd is available
        if (select_res == 0) continue;

        // Call handlers
        tcp_ev_loop_handler(&readfds, &writefds, &exceptfds);
    } while ((select_res = select(nfds, &readfds, &writefds, &exceptfds, NULL)) >= 0);
}

void print_usage() {
    printf("Usage: yapofw <config_file>\n");
}

int main(int argc, char **argv) {
    if (argc != 2) {
        print_usage();
        return -1;
    }

    size_t num = 0;
    config_item_t *config = parse_config(argv[1], &num);
    if (tcp_init_from_config(config, num) != 0) {
        printf("Error loading TCP connection configurations\n");
        return -1;
    }

    ev_loop();
}