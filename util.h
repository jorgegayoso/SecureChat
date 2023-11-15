#ifndef _UTIL_H_
#define _UTIL_H_

#include <netinet/in.h>

int lookup_host_ipv4(const char *hostname, struct in_addr *addr);
int max(int x, int y);
int parse_port(const char *str, uint16_t *port_p);
char* get_time();
char* remove_start_spaces(char *str);

#endif /* defined(_UTIL_H_) */
