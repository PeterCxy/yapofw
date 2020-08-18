#include "config.h"
#include "loop.h"
#include "tcp.h"
#include <signal.h>
#include <stdio.h>

void print_usage() {
    printf("Usage: yapofw <config_file>\n");
}

int main(int argc, char **argv) {
    if (argc != 2) {
        print_usage();
        return -1;
    }

    if (event_loop_init(1024) < 0) {
        printf("Failed initializing event loop\n");
        return -1;
    }

    size_t num = 0;
    config_item_t *config = parse_config(argv[1], &num);
    if (tcp_init_from_config(config, num) != 0) {
        printf("Error loading TCP connection configurations\n");
        return -1;
    }

    // We don't want SIGPIPE -- we will handle this as write() errors
    signal(SIGPIPE, SIG_IGN);
    event_loop();
}