#ifndef _SERVER_H_
#define _SERVER_H_

// Server settings
#define MAX_CHILDREN 16

// Worker settings
#define MAX_DATA_LENGTH 256

#define MIN_PASS_LENGTH 0

#define MAX_USER_LENGTH 16
#define MAX_PASS_LENGTH 64

// Moved to 'server.h' for clarity
struct server_child_state {
  int worker_fd;  /* server <-> worker bidirectional notification channel */
  int pending; /* notification pending yes/no */
};

struct server_state {
  int sockfd;
  struct server_child_state children[MAX_CHILDREN];
  int child_count;
};

int* get_children(struct server_state *state);

#endif /* defined(_SERVER_H_) */
