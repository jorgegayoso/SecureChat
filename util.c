#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>

#include "util.h"

#define MAX_STRING_LENGTH 1000

int lookup_host_ipv4(const char *hostname, struct in_addr *addr) {
  struct hostent *host;

  assert(hostname);
  assert(addr);

  /* look up hostname, find first IPv4 entry */
  host = gethostbyname(hostname);
  while (host) {
    if (host->h_addrtype == AF_INET &&
      host->h_addr_list &&
      host->h_addr_list[0]) {
      assert(host->h_length == sizeof(*addr));
      memcpy(addr, host->h_addr_list[0], sizeof(*addr));
      return 0;
    }
    host = gethostent();
  }

  fprintf(stderr, "error: unknown host: %s\n", hostname);
  return -1;
}

int max(int x, int y) {
  return (x > y) ? x : y;
}

int parse_port(const char *str, uint16_t *port_p) {
  char *endptr;
  long value;

  assert(str);
  assert(port_p);

  /* convert string to number */
  errno = 0;
  value = strtol(str, &endptr, 0);
  if (!value && errno) return -1;
  if (*endptr) return -1;

  /* is it a valid port number */
  if (value < 0 || value > 65535) return -1;

  *port_p = value;
  return 0;
}

char* get_time() {
    time_t t;
    struct tm *tm_info;
    char *time_str = (char*)malloc(20); // Adjust the size based on your format

    time(&t);
    tm_info = localtime(&t);

    snprintf(time_str, 20, "%04d-%02d-%02d %02d:%02d:%02d", 1900 + tm_info->tm_year, tm_info->tm_mon, tm_info->tm_mday, tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);

    return time_str;
}
