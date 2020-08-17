#pragma once
#include <netinet/ip.h>

typedef struct {
    int af; // AF_INET or AF_INET6
    union {
        struct in_addr addr4;
        struct in6_addr addr6;
    } addr;
    unsigned short port;
} config_addr_t;

typedef enum {
    TCP, UDP
} config_proto_t;

typedef struct {
    config_proto_t src_proto;
    config_addr_t src_addr;
    config_proto_t dst_proto;
    config_addr_t dst_addr;
} config_item_t;

// Parse text config from path
config_item_t *parse_config(const char *path, size_t *num_items);