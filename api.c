#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "api.h"

/**
 * @brief         Receive the next message from the sender and stored in @msg
 * @param state   Initialized API state
 * @param msg     Information about message is stored here
 * @return        Returns 1 on new message, 0 in case socket was closed,
 *                or -1 in case of error.
 */

int api_recv(struct api_state *state, struct api_msg *msg) {

  assert(state);
  assert(msg);

  ssize_t bytes_read;
  char buffer[256];

  bytes_read = read(state->fd, buffer, sizeof(buffer) - 1);

  if (bytes_read == -1) {
      perror("error: read socket failed");
      return -1;
  } else if (bytes_read == 0) {
      return 0;
  }

  buffer[bytes_read] = '\0';

  msg->data = strdup(buffer);
  if (msg->data == NULL) {
      perror("error: memory allocation for msg->data failed");
      return -1;
  }

  msg->length = bytes_read;

  return 1;
}

/**
 * @brief         Clean up information stored in @msg
 * @param msg     Information about message to be cleaned up
 */
void api_recv_free(struct api_msg *msg) {

  assert(msg);

  /* TODO clean up state allocated for msg */
}

/**
 * @brief         Frees api_state context
 * @param state   Initialized API state to be cleaned up
 */
void api_state_free(struct api_state *state) {

  assert(state);

  /* TODO clean up API state */
}

/**
 * @brief         Initializes api_state context
 * @param state   API state to be initialized
 * @param fd      File descriptor of connection socket
 */
void api_state_init(struct api_state *state, int fd) {

  assert(state);

  /* initialize to zero */
  memset(state, 0, sizeof(*state));

  /* store connection socket */
  state->fd = fd;

  /* TODO initialize API state */
}

int api_send(struct api_state *state, const char *message) {
  assert(state);
  assert(message);

  ssize_t sent_bytes = write(state->fd, message, strlen(message));

  if (sent_bytes == -1) {
    perror("error: write socket failed");
    return -1;
  }
  
  return 0;
}
