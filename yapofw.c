#include "config.h"
#include <stdio.h>

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
}