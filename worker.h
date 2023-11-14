#ifndef _WORKER_H_
#define _WORKER_H_

#include "api.h"

// Colors
#define RED "\x1b[31m"
#define ORANGE "\x1b[38;2;255;165;0m"
#define YELLOW "\x1b[33m"
#define GREEN "\x1b[32m"
#define RESET "\x1b[0m"

struct user_state {
  int online;
  char username[MAX_USER_LENGTH];
  char data[MAX_DATA_LENGTH];
  char *color;
};

struct worker_state {
  struct api_state api;
  int eof;
  int server_fd;  /* server <-> worker bidirectional notification channel */
  int server_eof;
  struct user_state user;
};

__attribute__((noreturn))
void worker_start(int connfd, int server_fd);

#endif /* !defined(_WORKER_H_) */
