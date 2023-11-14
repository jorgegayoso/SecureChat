#ifndef _SERVER_H_
#define _SERVER_H_

// Server settings
#define MAX_CHILDREN 16

// Worker settings
#define MAX_DATA_LENGTH 256

#define MIN_PASS_LENGTH 8

#define MAX_USER_LENGTH 16
#define MAX_PASS_LENGTH 64


struct server_child_state {
  int worker_fd;  /* server <-> worker bidirectional notification channel */
  int pending; /* notification pending yes/no */
};

struct server_state {
  int sockfd;
  struct server_child_state children[MAX_CHILDREN];
  int child_count;
};

#endif /* defined(_SERVER_H_) */
