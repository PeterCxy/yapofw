#include "util.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen) {
    switch (sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                    s, maxlen);
            break;
        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                    s, maxlen);
            break;
        default:
            strncpy(s, "Unknown AF", maxlen);
            return NULL;
    }

    return s;
}

int get_ip_port(const struct sockaddr *sa) {
    switch (sa->sa_family) {
        case AF_INET:
            return ntohs(((struct sockaddr_in *)sa)->sin_port);
        case AF_INET6:
            return ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
        default:
            return -1; // impossible
    }
}