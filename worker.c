#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "api.h"
#include "util.h"
#include "server.h"
#include "worker.h"


/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state *state, const char *msg) {
  if (strcmp(msg, "") == 0)
    return 0;
  if (state->user.online == 1)
    api_send(&state->api, msg);
  
  return 0;
}

/**
 * @brief         Notifies server that the worker received a new message
 *                from the client.
 * @param state   Initialized worker state
 */
/* TODO call this function to notify other workers through server */
__attribute__((unused))
static int notify_workers(struct worker_state *state, const char *msg) {
  ssize_t r;

  /* we only need to send something to notify the other workers,
   * data does not matter
   */
  r = write(state->server_fd, msg, MAX_DATA_LENGTH);
  if (r < 0 && errno != EPIPE) {
    perror("error: write of server_fd failed");
    return -1;
  }
  return 0;
}

static void check_file(char *name) {
  if (access(name, F_OK) != 0) {
        // File doesn't exist, create it
        FILE *file = fopen(name, "w");
        
        if (file == NULL) {
            perror("Error creating file");
            return;
        }
        
        fclose(file);
    }
}

static int handle_user_registration(struct worker_state *state, int is_login, char *user, char *password) {
  check_file("users.db");
  FILE *file = fopen("users.db", "r+");
  
  if (file == NULL) {
      perror("Error opening file");
      snprintf(state->user.data, MAX_DATA_LENGTH, "Error registering " YELLOW "user" RESET);
      return 0;
  }

  char line[MAX_DATA_LENGTH];

  while (fgets(line, sizeof(line), file) != NULL) {
      // Process each row
      char *token = strtok(line, "\t");
      int count = 0;
      int is_user = 0;
      
      while (token != NULL) {
        // Process each field
        if (is_user == 1 && count == 1) {
          token[strlen(token) - 1] = '\0';
          if (strcmp(password, token) == 0) {
            snprintf(state->user.username, MAX_DATA_LENGTH, "%s", user);
            snprintf(state->user.data, MAX_DATA_LENGTH, "authentication succeeded");
            fclose(file);
            return 1;
          } else {
            snprintf(state->user.data, MAX_DATA_LENGTH, YELLOW "Username" RESET " or " YELLOW "password " RED "incorrect" RESET);
            fclose(file);
            return 0;
          }
        }

        is_user = 0;

        if (count == 0 && strcmp(user, token) == 0) {
          if (is_login == 1) {
            is_user = 1;
          } else {
            snprintf(state->user.data, MAX_DATA_LENGTH, YELLOW "Username" ORANGE " already exists" RESET);
            fclose(file);
            return 0;
          }
        }
        
        // Move to the next field
        token = strtok(NULL, "\t");
        count++;
      }
  }

  fseek(file, 0, SEEK_END);
  fprintf(file, "%s\t%s\n", user, password);

  fclose(file);

  if (is_login) {
    snprintf(state->user.data, MAX_DATA_LENGTH, "error: invalid command format");
    return 0;
  }

  //snprintf(state->user.data, MAX_DATA_LENGTH, YELLOW "User" RESET " registered " GREEN "correctly" YELLOW "\nLogged in" RESET " as %s%s" RESET, state->user.color, user);
  snprintf(state->user.data, MAX_DATA_LENGTH, "registration succeeded");
  snprintf(state->user.username, MAX_DATA_LENGTH, "%s", user);
  return 1;
}

static void save_chat(struct worker_state *state) {
  // Save a new line to 'chat.db'
  check_file("chat.db");
  FILE *file = fopen("chat.db", "r+");
  
  if (file == NULL) {
      perror("Error opening file");
      snprintf(state->user.data, MAX_DATA_LENGTH, "Error sending " YELLOW "message" RESET);
      return;
  }
  
  fseek(file, 0, SEEK_END);
  fprintf(file, "%s\n", state->user.data);

  fclose(file);
}

static void send_chat(struct worker_state *state) {
  // Send all lines on 'chat.db' to client
  check_file("chat.db");
  FILE *file = fopen("chat.db", "r+");
  
  if (file == NULL) {
      perror("Error opening file");
      snprintf(state->user.data, MAX_DATA_LENGTH, "Error sending " YELLOW "message" RESET);
      return;
  }

  char line[MAX_DATA_LENGTH];
  
  while (fgets(line, sizeof(line), file) != NULL) {
    // Process each row
    char *token = strtok(line, "\t");
    
    while (token != NULL) {
      // Process each field
      api_send(&state->api, token);
      
      // Move to the next field
      token = strtok(NULL, "\t");
    }
  }

  fclose(file);
}

/**
 * @brief         Handles a message coming from client
 * @param state   Initialized worker state
 * @param msg     Message to handle
 */
static int execute_request(struct worker_state *state, const struct api_msg *msg) {
  char *time = get_time();
  char buffer[MAX_DATA_LENGTH - strlen(state->user.username) - strlen(time) - 2];
  strcpy(buffer, msg->data);
  
  int count = 0;
  char *words[5];
  char *token = strtok(msg->data, " ");

  while (token != NULL && count < 5) { // Divide string into words
      words[count] = token;
      count++;
      token = strtok(NULL, " ");
  }

  if (strcmp(words[0], "/logout") == 0) { // Handle logout command (optional)
    if (count != 1) // If invalid parameter amount
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: invalid command format");
    if (state->user.online == 0) { // If not logged in
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: command not currently available");
    } else { // Log out
      state->user.online = 0;
      snprintf(state->user.data, MAX_DATA_LENGTH, YELLOW "Logged out" RESET);
    }
  } else if (strcmp(words[0], "/users") == 0) { // Not implemented
    if (count != 1) // If invalid parameter amount
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: invalid command format");
    else if (state->user.online == 0) {
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: command not currently available");
    } else {
      state->user.online = 0;
      snprintf(state->user.data, MAX_DATA_LENGTH, YELLOW "Logged out" RESET);
    }
  } else if (strcmp(words[0], "/color") == 0) { // Change user color (redundant due to test.py)
    if (count != 2) // If invalid parameter amount
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: invalid command format");
    if (strcmp(words[1], "red") == 0) {
      state->user.color = RED;
      snprintf(state->user.data, MAX_DATA_LENGTH, "Color changed to " RED "red" RESET);
    } else if (strcmp(words[1], "orange") == 0) {
      state->user.color = ORANGE;
      snprintf(state->user.data, MAX_DATA_LENGTH, "Color changed to " ORANGE "orange" RESET);
    } else if (strcmp(words[1], "yellow") == 0) {
      state->user.color = YELLOW;
      snprintf(state->user.data, MAX_DATA_LENGTH, "Color changed to " YELLOW "yellow" RESET);
    } else if (strcmp(words[1], "green") == 0) {
      state->user.color = GREEN;
      snprintf(state->user.data, MAX_DATA_LENGTH, "Color changed to " GREEN "green" RESET);
    } else {
      snprintf(state->user.data, MAX_DATA_LENGTH, "Unknown color");
    }
  } else if (strcmp(words[0], "/register") == 0) { // Handle register command
    if (count != 3) { // If invalid parameter amount
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: invalid command format");
    
    // Handle /register command
    } else if (state->user.online == 1) { // If already logged in
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: command not currently available");
    } else if (strchr(words[1], '\t') != NULL) { // If invalid delimiter character in username
      snprintf(state->user.data, MAX_DATA_LENGTH, YELLOW "Username" RESET " contains " RED "invalid" RESET " character: '\t'");
    } else if (strchr(words[2], '\t') != NULL) { // If invalid delimiter character in password
      snprintf(state->user.data, MAX_DATA_LENGTH, YELLOW "Password" RESET " contains " RED "invalid" RESET " character: '\t'");
    } else if (strlen(words[1]) > MAX_USER_LENGTH) { // If username too long
      snprintf(state->user.data, MAX_DATA_LENGTH, YELLOW "Username" RESET " must be " YELLOW "%d characters" RESET " or " ORANGE "less" RESET, MAX_USER_LENGTH);
    } else if (strlen(words[2]) < MIN_PASS_LENGTH) { // If password too short
      snprintf(state->user.data, MAX_DATA_LENGTH, YELLOW "Password" RESET " must be " YELLOW "%d characters" RESET " or " ORANGE "more" RESET, MIN_PASS_LENGTH);
    } else if (strlen(words[2]) > MAX_PASS_LENGTH) { // If password too long
      snprintf(state->user.data, MAX_DATA_LENGTH, YELLOW "Password" RESET " must be " YELLOW "%d characters" RESET " or " ORANGE "less" RESET, MAX_PASS_LENGTH);
    } else { // Try register
      state->user.online = handle_user_registration(state, 0, words[1], words[2]);
      if (state->user.online == 1) { // If successful, register and login
        api_send(&state->api, state->user.data);
        send_chat(state); // Send all past chats
        return 0;
      }
    }
  } else if (strcmp(words[0], "/login") == 0) { // Handle login command
    if (count != 3) { // If invalid parameter amount
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: invalid command format");
    } else if (state->user.online == 1) { // If already logged in
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: command not currently available");
    } else { // Try login
      state->user.online = handle_user_registration(state, 1, words[1], words[2]);
      if (state->user.online == 1) { // If successful, login
        api_send(&state->api, state->user.data);
        send_chat(state); // Send all past chats
        return 0;
      }
    }
  } else if (words[0][0] == '/') { // If invalid command
    snprintf(state->user.data, MAX_DATA_LENGTH, "error: unknown command %s", words[0]);
  } else { // If command is message
    if (state->user.online) { // If logged in
      snprintf(state->user.data, MAX_DATA_LENGTH, "%s %s: %s", time, state->user.username, buffer);
      save_chat(state);
      notify_workers(state, state->user.data);
      return 0;
    } else { // If not logged in
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: command not currently available");
    }
  }

  api_send(&state->api, state->user.data);
  return 0;
}

/**
 * @brief         Reads an incoming request from the client and handles it.
 * @param state   Initialized worker state
 */
static int handle_client_request(struct worker_state *state) {
  struct api_msg msg;
  int r, success = 1;

  assert(state);

  /* wait for incoming request, set eof if there are no more requests */
  
  r = api_recv(&state->api, &msg);
  if (r < 0) return -1;
  if (r == 0) {
    state->eof = 1;
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

static int handle_s2w_read(struct worker_state *state) {
  char buf[MAX_DATA_LENGTH];
  ssize_t r;

  /* notification from the server that the workers must notify their clients
   * about new messages; these notifications are idempotent so the number
   * does not actually matter, nor does the data sent over the pipe
   */
  errno = 0;
  r = read(state->server_fd, buf, sizeof(buf));
  if (r < 0) {
    perror("error: read server_fd failed");
    return -1;
  }
  if (r == 0) {
    state->server_eof = 1;
    return 0;
  }

  /* notify our client */
  if (handle_s2w_notification(state, buf) != 0) return -1;

  return 0;
}

/**
 * @brief Registers for: client request events, server notification
 *        events. In case of a client request, it processes the
 *        request and sends a response to client. In case of a server
 *        notification it notifies the client of all newly received
 *        messages.
 *
 */
static int handle_incoming(struct worker_state *state) {
  int fdmax, r, success = 1;
  fd_set readfds;

  assert(state);

  /* list file descriptors to wait for */
  FD_ZERO(&readfds);
  /* wake on incoming messages from client */
  FD_SET(state->api.fd, &readfds);
  /* wake on incoming server notifications */
  if (!state->server_eof) FD_SET(state->server_fd, &readfds);
  fdmax = max(state->api.fd, state->server_fd);

  /* wait for at least one to become ready */
  r = select(fdmax+1, &readfds, NULL, NULL, NULL);
  if (r < 0) {
    if (errno == EINTR) return 0;
    perror("error: select failed");
    return -1;
  }

  /* handle ready file descriptors */
  /* TODO once you implement encryption you may need to call ssl_has_data
   * here due to buffering (see ssl-nonblock example)
   */
  if (FD_ISSET(state->api.fd, &readfds)) {
    if (handle_client_request(state) != 0) success = 0;
  }
  if (FD_ISSET(state->server_fd, &readfds)) {
    if (handle_s2w_read(state) != 0) success = 0;
  }
  return success ? 0 : -1;
}

/**
 * @brief Initialize struct worker_state before starting processing requests.
 * @param state        worker state
 * @param connfd       connection file descriptor
 * @param pipefd_w2s   pipe to notify server (write something to notify)
 * @param pipefd_s2w   pipe to be notified by server (can read when notified)
 *
 */
static int worker_state_init(struct worker_state *state, int connfd, int server_fd) {

  /* initialize */
  memset(state, 0, sizeof(*state));
  state->server_fd = server_fd;

  /* set up API state */
  api_state_init(&state->api, connfd);

  state->user.online = 0;
  state->user.color = GREEN;

  return 0;
}

/**
 * @brief Clean up struct worker_state when shutting down.
 * @param state        worker state
 *
 */
static void worker_state_free(
  struct worker_state *state) {
  /* TODO any additional worker state cleanup */

  /* clean up API state */
  api_state_free(&state->api);

  /* close file descriptors */
  close(state->server_fd);
  close(state->api.fd);
}

/**
 * @brief              Worker entry point. Called by the server when a
 *                     worker is spawned.
 * @param connfd       File descriptor for connection socket
 * @param pipefd_w2s   File descriptor for pipe to send notifications
 *                     from worker to server
 * @param pipefd_s2w   File descriptor for pipe to send notifications
 *                     from server to worker
 */
__attribute__((noreturn))
void worker_start(int connfd, int server_fd) {
  struct worker_state state;
  int success = 1;

  /* initialize worker state */
  if (worker_state_init(&state, connfd, server_fd) != 0) {
    goto cleanup;
  }
  /* TODO any additional worker initialization */

  /* handle for incoming requests */
  while (!state.eof) {
    if (handle_incoming(&state) != 0) {
      success = 0;
      break;
    }
  }

cleanup:
  /* cleanup worker */
  /* TODO any additional worker cleanup */
  worker_state_free(&state);

  exit(success ? 0 : 1);
}
