#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>

#include "api.h"
#include "ui.h"
#include "util.h"

// ----- STRUCTS -----
struct client_state {
  struct api_state api;
  int eof;
  struct ui_state ui;
  SSL_CTX *ssl_ctx;
};

// ----- MAIN -----
/**
 * @brief Connects to @hostname on port @port and returns the
 *        connection fd. Fails with -1.
 */
static SSL *client_connect(struct client_state *state, const char *hostname, uint16_t port) {
  int fd;
  struct sockaddr_in addr;

  assert(state);
  assert(hostname);

  /* look up hostname */
  if (lookup_host_ipv4(hostname, &addr.sin_addr) != 0) return NULL;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  /* create TCP socket */
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("error: cannot allocate server socket");
    return NULL;
  }

  /* connect to server */
  if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
    perror("error: cannot connect to server");
    close(fd);
    return NULL;
  }

  // Set up SSL on the socket
  SSL *ssl = SSL_new(state->ssl_ctx);
  SSL_set_fd(ssl, fd);

  if (SSL_connect(ssl) <= 0) {
      ERR_print_errors_fp(stderr);
      close(fd);
      return NULL;
  }

  return ssl;
}

static int client_process_command(struct client_state *state) {
  assert(state);

  char buffer[256];
  char delimiters[] = " \t\n";
  char *words[5];
  int count = 0;
  
  if (fgets(buffer, sizeof(buffer), stdin) == NULL) { // Read from stdin
      state->eof = 1;
      return -1;
  }

  char *last_new_line = strrchr(buffer, '\n');
  if (last_new_line != NULL)
      *last_new_line = '\0';

  char message[256];
  strcpy(message, buffer);

  char *token = strtok(buffer, delimiters);
  while (token != NULL && count < 5) { // Divide buffer to words
      words[count] = token;
      count++;
      token = strtok(NULL, delimiters);
  }

  if (count == 1 && strcmp(words[0], "/exit") == 0) { // Handle exit command
    state->eof = 1;
  } else { // Send input to worker
    api_send(&state->api, message);
  }

  return 0;
}

/**
 * @brief         Handles a message coming from server (i.e, worker)
 * @param state   Initialized client state
 * @param msg     Message to handle
 */
static int execute_request(
  struct client_state *state,
  const struct api_msg *msg) {

  printf("%s\n", msg->data); // Print response to stdout

  return 0;
}

/**
 * @brief         Reads an incoming request from the server and handles it.
 * @param state   Initialized client state
 */
static int handle_server_request(struct client_state *state) {
  struct api_msg msg;
  int r, success = 1;

  assert(state);

  /* wait for incoming request, set eof if there are no more requests */
  r = api_recv(&state->api, &msg);
  if (r < 0) return -1;
  if (r == 0) {
    return 0;
  }

  /* execute request */
  if (execute_request(state, &msg) != 0) {
    success = 0;
  }

  /* clean up state associated with the message */
  api_recv_free(&msg);

  return success ? 0 : -1;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl");
        return -1;
    }
    return 0;
}

/**
 * @brief register for multiple IO event, process one
 *        and return. Returns 0 if the event was processed
 *        successfully and -1 otherwise.
 *
 */
static int handle_incoming(struct client_state *state) {
  int fdmax, r;
  fd_set readfds;

  assert(state);

  // Set non-blocking SSL
  if (set_nonblocking(SSL_get_fd(state->api.ssl)) == -1) {
    return -1;
  }

  /* list file descriptors to wait for */
  FD_ZERO(&readfds);
  FD_SET(STDIN_FILENO, &readfds);
  FD_SET(SSL_get_fd(state->api.ssl), &readfds);
  fdmax = SSL_get_fd(state->api.ssl);

  /* wait for at least one to become ready */
  r = select(fdmax+1, &readfds, NULL, NULL, NULL);
  if (r < 0) {
    if (errno == EINTR) return 0;
    perror("error: select failed");
    return -1;
  }

  /* handle ready file descriptors */
  if (FD_ISSET(STDIN_FILENO, &readfds)) {
    return client_process_command(state);
  }
  
  if (FD_ISSET(SSL_get_fd(state->api.ssl), &readfds)) {
    return handle_server_request(state);
  }
  return 0;
}

static int client_state_init(struct client_state *state) {
  /* clear state, invalidate file descriptors */
  memset(state, 0, sizeof(*state));

  /* initialize UI */
  ui_state_init(&state->ui);

  // Initialize SSL
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  state->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  
  // Load server's public certificate
  if (SSL_CTX_use_certificate_file(state->ssl_ctx, "clientkeys/X509_Certificate.crt", SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  return 0;
}

static void client_state_free(struct client_state *state) {

  /* TODO any additional client state cleanup */

  /* cleanup API state */
  api_state_free(&state->api);

  /* cleanup UI state */
  ui_state_free(&state->ui);
}

static void usage(void) {
  printf("usage:\n");
  printf("  client host port\n");
  exit(1);
}

int main(int argc, char **argv) {
  SSL *ssl;
  uint16_t port;
  struct client_state state;

  /* check arguments */
  if (argc != 3) usage();
  if (parse_port(argv[2], &port) != 0) usage();

  /* preparations */
  client_state_init(&state);

  /* connect to server */
  ssl = client_connect(&state, argv[1], port);
  if (SSL_get_fd(ssl) < 0) return 1;

  /* initialize API */
  api_state_init(&state.api, ssl);

  /* TODO any additional client initialization */
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("connected to server %s:%d\n", argv[1], port);

  /* client things */
  while (!state.eof && handle_incoming(&state) == 0);

  /* clean up */
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(state.ssl_ctx);

  client_state_free(&state);
  close(SSL_get_fd(ssl));

  return 0;
}
