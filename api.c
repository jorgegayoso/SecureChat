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

  bytes_read = SSL_read(state->ssl, buffer, sizeof(buffer) - 1);
  
  if (bytes_read == -1) {
    int ssl_error = SSL_get_error(state->ssl, bytes_read);
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
      return 0;
    } else if (ssl_error != 1) {
      perror("error: read socket failed");
      return -1;
    }

    int ssl_shutdown = SSL_get_shutdown(state->ssl);
    if (ssl_shutdown == 0) {
      printf("server disconnected\n");
      return -1;
    }
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
void api_state_init(struct api_state *state, SSL *ssl) {

  assert(state);

  /* initialize to zero */
  memset(state, 0, sizeof(*state));

  // Store SSL instance
  state->ssl = ssl;
}

int api_send(struct api_state *state, const char *message) {
  assert(state);
  assert(message);

  ssize_t sent_bytes = SSL_write(state->ssl, message, strlen(message));

  if (sent_bytes == -1) {
    perror("error: write socket failed");
    return -1;
  }
  
  return 0;
}
