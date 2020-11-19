#include "config.h"
#include "loop.h"
#include "stats.h"
#include "tcp.h"
#include "udp.h"
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>

void print_usage() {
    printf("Usage: yapofw <config_file> [stats_persist_file]\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return -1;
    }

    // Retrieve RLIMIT_NOFILE for use with event loop
    struct rlimit nofile_limit;
    getrlimit(RLIMIT_NOFILE, &nofile_limit);

    // The event loop MUST be initialized with RLIMIT_NOFILE
    if (event_loop_init(nofile_limit.rlim_cur) < 0) {
        printf("Failed initializing event loop\n");
        return -1;
    }

    size_t num = 0;
    config_item_t *config = parse_config(argv[1], &num);

    if (config == NULL) {
        return -1;
    }

    if (argc >= 3 && stats_init_from_config(config, num, argv[2]) != 0) {
        printf("Error initializing the stats module\n");
        return -1;
    }

    if (tcp_init_from_config(config, num) != 0) {
        printf("Error loading TCP connection configurations\n");
        return -1;
    }

    if (udp_init_from_config(config, num) != 0) {
        printf("Error loading UDP configurations\n");
        return -1;
    }

    // We don't want SIGPIPE -- we will handle this as write() errors
    signal(SIGPIPE, SIG_IGN);
    event_loop();
}