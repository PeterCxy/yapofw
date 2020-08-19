#include "config.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *ltrim(char *s) {
    while (isspace(*s)) s++;
    return s;
}

char *rtrim(char *s) {
    char* back = s + strlen(s);
    while (isspace(*--back));
    *(back + 1) = '\0';
    return s;
}

char *trim(char *s) {
    return rtrim(ltrim(s)); 
}

int parse_proto(char *s_proto, config_proto_t *proto, config_addr_t *addr_info) {
    if (strcmp(s_proto, "tcp") == 0) {
        *proto = TCP;
        addr_info->af = AF_INET;
        return 0;
    } else if (strcmp(s_proto, "tcp6") == 0) {
        *proto = TCP;
        addr_info->af = AF_INET6;
        return 0;
    } else if (strcmp(s_proto, "udp") == 0) {
        *proto = UDP;
        addr_info->af = AF_INET;
        return 0;
    } else if (strcmp(s_proto, "udp6") == 0) {
        *proto = UDP;
        addr_info->af = AF_INET6;
        return 0;
    } else {
        return -1;
    }
}

int parse_addr(char *s_addr, config_addr_t *addr_info) {
    int ch = ':';
    char *port_ptr = strrchr(s_addr, ch);
    if (port_ptr == NULL || s_addr + strlen(s_addr) <= port_ptr) {
        return -1;
    }

    addr_info->port = atoi(port_ptr + 1);

    char ip_addr[255];
    memcpy(ip_addr, s_addr, port_ptr - s_addr);
    ip_addr[port_ptr - s_addr] = '\0';

    if (inet_pton(addr_info->af, ip_addr, &addr_info->addr) != 1) {
        return -1;
    }

    return 0;
}

config_item_t *parse_line(char *line) {
    // Make a copy for use with strtok
    char *_line_copy = malloc(strlen(line));
    if (_line_copy == NULL) return NULL;
    strcpy(_line_copy, line);
    char *line_copy = trim(_line_copy);
    
    enum {
        START, SRC_PROTO_READ, SRC_ADDR_READ, DST_PROTO_READ, FINAL
    } line_parse_state = START;
    config_item_t *ret = malloc(sizeof(config_item_t));
    if (ret == NULL) return NULL;
    memset(ret, 0, sizeof(config_item_t));

    char *token = strtok(line_copy, " ");
    do {
        switch (line_parse_state) {
            case START:
                if (parse_proto(token, &ret->src_proto, &ret->src_addr) != 0) {
                    printf("Invalid src protocol %s\n", token);
                    goto error_out;
                }
                line_parse_state = SRC_PROTO_READ;
                break;
            case SRC_PROTO_READ:
                if (parse_addr(token, &ret->src_addr) != 0) {
                    printf("Invalid src address %s\n", token);
                    goto error_out;
                }
                line_parse_state = SRC_ADDR_READ;
                break;
            case SRC_ADDR_READ:
                if (parse_proto(token, &ret->dst_proto, &ret->dst_addr) != 0) {
                    printf("Invalid dst protocol %s\n", token);
                    goto error_out;
                }
                line_parse_state = DST_PROTO_READ;
                break;
            case DST_PROTO_READ:
                if (parse_addr(token, &ret->dst_addr) != 0) {
                    printf("Invalid dst address %s\n", token);
                    goto error_out;
                }
                line_parse_state = FINAL;
                break;
            case FINAL:
                printf("Unexpected token: %s\n", token);
                goto error_out;
        }
    } while ((token = strtok(NULL, " ")) != NULL);

    if (line_parse_state != FINAL) {
        printf("Invalid config line %s\n", line);
        goto error_out;
    }

    free(line_copy);
    return ret;

error_out:
    free(line_copy);
    free(ret);
    return NULL;
}

config_item_t *parse_config(const char *path, size_t *num_items) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL)
        return NULL;

    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    // Count the number of lines first
    *num_items = 0;
    while ((read = getline(&line, &len, fp)) != -1) {
        (*num_items)++;
    }

    // Read config line by line
    fseek(fp, 0, SEEK_SET);
    config_item_t *items = malloc(sizeof(config_item_t) * (*num_items));
    if (items == NULL) return NULL;
    size_t i = 0;
    while ((read = getline(&line, &len, fp)) != -1) {
        config_item_t *item = parse_line(line);
        if (item == NULL) {
            printf("Invalid config\n");
            free(items);
            return NULL;
        }
        items[i] = *item;
        free(item);
        i++;
    }

    fclose(fp);

    return items;
}

struct sockaddr *config_addr_to_sockaddr(config_addr_t *addr, size_t *sockaddr_len) {
    if (addr->af == AF_INET) {
        struct sockaddr_in *ret = malloc(sizeof(struct sockaddr_in));
        if (ret == NULL) return NULL;
        memset(ret, 0, sizeof(struct sockaddr_in));
        ret->sin_family = AF_INET;
        ret->sin_port = htons(addr->port);
        ret->sin_addr = addr->addr.addr4;
        *sockaddr_len = sizeof(struct sockaddr_in);
        return (struct sockaddr *) ret;
    } else if (addr->af == AF_INET6) {
        struct sockaddr_in6 *ret = malloc(sizeof(struct sockaddr_in6));
        if (ret == NULL) return NULL;
        memset(ret, 0, sizeof(struct sockaddr_in6));
        ret->sin6_family = AF_INET6;
        ret->sin6_port = htons(addr->port);
        ret->sin6_addr = addr->addr.addr6;
        *sockaddr_len = sizeof(struct sockaddr_in6);
        return (struct sockaddr *) ret;
    } else {
        return NULL;
    }
}

char *config_addr_to_str(config_addr_t *addr, char *str, size_t len) {
    inet_ntop(addr->af, &addr->addr, str, len);
    return str;
}