#pragma once
#include <sys/socket.h>

char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);
int get_ip_port(const struct sockaddr *sa);
int sockaddr_cmp(struct sockaddr *x, struct sockaddr *y);