#pragma once
#include <netinet/ip.h>
#include <sys/socket.h>

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
    config_addr_t *failover_addrs;
    size_t failover_addrs_num;
} config_item_t;

// Parse text config from path
config_item_t *parse_config(const char *path, size_t *num_items);
// Convert config_addr_t to sockaddr
struct sockaddr *config_addr_to_sockaddr(config_addr_t *addr, size_t *sockaddr_len);
char *config_addr_to_str(config_addr_t *addr, char *str, size_t len);