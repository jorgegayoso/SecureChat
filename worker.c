#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "api.h"
#include "util.h"
#include "server.h"
#include "worker.h"


/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state *state, char *msg) {
  if (strcmp(msg, "") == 0)
    return 0;
  
  // TODO: Implement decryption of server message with client private key
  
  char buffer[MAX_DATA_LENGTH];
  strcpy(buffer, msg);
  char *word = strtok(msg, "\t");
  
  // sending of messages
  if (word[0] == '@') {

    char match_user[sizeof(state->user.username) + 1];
    snprintf(match_user, sizeof(match_user), "@%s", state->user.username);
    if (strcmp(word, match_user) == 0) {
      api_send(&state->api, strtok(NULL, ""));
    }

  } else if (state->user.online == 1) {
    api_send(&state->api, buffer);
  }

  return 0;
}

/**
 * @brief         Notifies server that the worker received a new message
 *                from the client.
 * @param state   Initialized worker state
 */
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

static char *generate_hash(char *buf) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_DigestInit(ctx, EVP_sha256());

  ssize_t len = strlen(buf);
  EVP_DigestUpdate(ctx, buf, len);
  
  unsigned char *hash = (unsigned char *)malloc(MAX_DATA_LENGTH);
  unsigned int hashlen = 0;

  EVP_DigestFinal(ctx, hash, &hashlen);
  EVP_MD_CTX_free(ctx);

  return (char *)hash;
}

static int add_user(struct worker_state *state, const char *username, char *password) {
  sqlite3 *db; // Open 'chat.db' file
  char *err = 0;
  int succeeded = 0;
  int rc = sqlite3_open("chat.db", &db);

  if (rc != SQLITE_OK) {
    snprintf(state->user.data, MAX_DATA_LENGTH, "Cannot open database: %s", sqlite3_errmsg(db));
    return 0;
  }

  // Check if the username already exists
  const char *username_str = "SELECT * FROM users WHERE username = ?;";
  sqlite3_stmt *stmt;

  rc = sqlite3_prepare_v2(db, username_str, -1, &stmt, 0);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "3 SQL error: %s\n", sqlite3_errmsg(db));
    exit(rc);
  }
  sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

  if (sqlite3_step(stmt) == SQLITE_ROW) {
    snprintf(state->user.data, MAX_DATA_LENGTH, "error: user %s already exists", username);
  } else {
    // Add the new user
    const char *insert_str = "INSERT INTO users (username, password, online) VALUES (?, ?, 1);";

    rc = sqlite3_prepare_v2(db, insert_str, -1, &stmt, 0);

    if (rc != SQLITE_OK) {
      fprintf(stderr, "4 SQL error: %s\n", sqlite3_errmsg(db));
      exit(rc);
    }

    // Generate and store hash
    char *hash = generate_hash(password);

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hash, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
      sqlite3_exec(db, "ROLLBACK;", 0, 0, 0);
      fprintf(stderr, "5 SQL error: %s\n", err);
      sqlite3_free(err);
      exit(rc);
    } else {
      rc = sqlite3_exec(db, "COMMIT;", 0, 0, &err);
      snprintf(state->user.username, MAX_DATA_LENGTH, "%s", username);
      snprintf(state->user.data, MAX_DATA_LENGTH, "registration succeeded");
      succeeded = 1;
    } free(hash);
  }

  // Close database
  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return succeeded;
}

static void set_online_status(const char *user, int online) {
  if (!user) { // Empty username check
    return;
  }

  sqlite3 *db; // Open 'chat.db' file
  char *err = 0;

  int rc = sqlite3_open("chat.db", &db);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
    exit(rc);
  }

  const char *update_online = "UPDATE users SET online = ? WHERE username = ?;";
  sqlite3_stmt *stmt;

  rc = sqlite3_prepare_v2(db, update_online, -1, &stmt, 0);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "6 SQL error: %s\n", sqlite3_errmsg(db));
    exit(rc);
  }
  char buf[MAX_DATA_LENGTH];
  sprintf(buf, "%d", online);

  sqlite3_bind_text(stmt, 1, buf, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, user, -1, SQLITE_STATIC);

  rc = sqlite3_step(stmt);

  if (rc == SQLITE_DONE) {
    rc = sqlite3_exec(db, "COMMIT;", 0, 0, &err);
  }
  
  // Close database
  sqlite3_finalize(stmt);
  sqlite3_close(db);
}

static int authenticate_user(struct worker_state *state, const char *username, char *password) {
  sqlite3 *db; // Open 'chat.db' file
  int rc = sqlite3_open("chat.db", &db);

  if (rc != SQLITE_OK)
    exit(rc);

  // Check if the username exists
  const char *user_str = "SELECT * FROM users WHERE username = ?;";
  sqlite3_stmt *stmt;

  rc = sqlite3_prepare_v2(db, user_str, -1, &stmt, 0);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "8 SQL error: %s\n", sqlite3_errmsg(db));
    exit(rc);
  }

  sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

  if (sqlite3_step(stmt) == SQLITE_ROW) { // Username exists, check if password hashes match
    const char *stored_password = (const char *)sqlite3_column_text(stmt, 1);
    char *hash = generate_hash(password);

    if (strcmp(stored_password, hash) == 0) { // Authentication succeeded
      snprintf(state->user.username, MAX_DATA_LENGTH, "%s", username);
      snprintf(state->user.data, MAX_DATA_LENGTH, "authentication succeeded");
      sqlite3_finalize(stmt);
      sqlite3_close(db);
      free(hash);
      return 1;
    } else { // Incorrect password
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: invalid credentials");
      sqlite3_finalize(stmt);
      sqlite3_close(db);
      free(hash);
      return 0;
    }
  } else { // Username does not exist
    snprintf(state->user.data, MAX_DATA_LENGTH, "error: invalid credentials");
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
  }
}

static void add_chat_entry(const char *time, const char *user, const char *privacy, const char *message) {
  sqlite3 *db; // Open 'chat.db' file
  char *err = 0;
  int rc = sqlite3_open("chat.db", &db);

  if (rc != SQLITE_OK)
    exit(rc);

  // Begin a transaction
  rc = sqlite3_exec(db, "BEGIN TRANSACTION;", 0, 0, &err);

  if (rc != SQLITE_OK) {
    sqlite3_free(err);
    exit(rc);
  }

  // Add the new entry to the chat
  const char *insertEntrySQL = "INSERT INTO messages (time, user, privacy, message) VALUES (?, ?, ?, ?);";
  sqlite3_stmt *stmt;
  rc = sqlite3_prepare_v2(db, insertEntrySQL, -1, &stmt, 0);

  if (rc != SQLITE_OK)
    exit(rc);

  sqlite3_bind_text(stmt, 1, time, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, user, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 3, privacy, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 4, message, -1, SQLITE_STATIC);

  rc = sqlite3_step(stmt);

  if (rc != SQLITE_DONE) { // Rollback the transaction in case of an error
    sqlite3_finalize(stmt);
    sqlite3_exec(db, "ROLLBACK;", 0, 0, 0);
    exit(rc);
  } else { // Commit the transaction
    rc = sqlite3_exec(db, "COMMIT;", 0, 0, &err);

    if (rc != SQLITE_OK) {
      sqlite3_free(err);
      exit(rc);
    }
  }

  // Close database
  sqlite3_finalize(stmt);
  sqlite3_close(db);
}

static void send_chat_entries(struct worker_state *state) {
  sqlite3 *db;

  int rc = sqlite3_open("chat.db", &db);

  if (rc != SQLITE_OK)
    exit(rc);

  // Select all entries from the chat in chronological order
  const char *select_str = "SELECT time, user, privacy, message FROM messages;";
  sqlite3_stmt *stmt;
  rc = sqlite3_prepare_v2(db, select_str, -1, &stmt, 0);

  if (rc != SQLITE_OK)
    exit(rc);

  char res[MAX_DATA_LENGTH]; // Data to send
  char user_symbol[sizeof(state->user.username) + 1]; // Used to compare with @username
  snprintf(user_symbol, sizeof(user_symbol), "@%s", state->user.username);

  // Process each entry
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const char *time = (const char *)sqlite3_column_text(stmt, 0);
    const char *user = (const char *)sqlite3_column_text(stmt, 1);
    const char *privacy = (const char *)sqlite3_column_text(stmt, 2);
    const char *message = (const char *)sqlite3_column_text(stmt, 3);

    if (privacy[0] == '@') {
      if (strcmp(user, state->user.username) == 0 || strcmp(privacy, user_symbol) == 0) {
        snprintf(res, MAX_DATA_LENGTH, "%s %s: %s\n", time, user, message);
        api_send(&state->api, res);
      }
    } else {
      snprintf(res, MAX_DATA_LENGTH, "%s %s: %s\n", time, user, message);
      api_send(&state->api, res);
    }
  }

  // Finalize the statement and close the database
  sqlite3_finalize(stmt);
  sqlite3_close(db);
}

static int check_user_exists(struct worker_state *state, const char *target_user) {
  sqlite3 *db; // Open 'chat.db' file
  int rc = sqlite3_open("chat.db", &db);
  int res = 0;

  if (rc != SQLITE_OK) {
    snprintf(state->user.data, MAX_DATA_LENGTH, "Cannot open database: %s", sqlite3_errmsg(db));
    return 0;
  }

  // Check if the user exists
  const char *username_str = "SELECT * FROM users WHERE username = ?;";
  sqlite3_stmt *stmt;

  rc = sqlite3_prepare_v2(db, username_str, -1, &stmt, 0);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "10 SQL error: %s", sqlite3_errmsg(db));
    exit(rc);
  }

  sqlite3_bind_text(stmt, 1, target_user, -1, SQLITE_STATIC);

  if (sqlite3_step(stmt) == SQLITE_ROW) {
    res = 1;
  }

  // Close database
  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return res;
}

static void send_online_users(struct worker_state *state) {
  sqlite3 *db; // Open 'chat.db' file
  int rc = sqlite3_open("chat.db", &db);
  if (rc != SQLITE_OK)
    exit(rc);
  
  const char *select_str = "SELECT username FROM users WHERE online = 1;"; // Select online users
  sqlite3_stmt *stmt;
  rc = sqlite3_prepare_v2(db, select_str, -1, &stmt, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "9 SQL error: %s\n", sqlite3_errmsg(db));
    exit(rc);
  }

  for (;;) { // Send online users, one by one
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE)
        break;
    if (rc != SQLITE_ROW) {
        printf("error: %s!\n", sqlite3_errmsg(db));
        break;
    }

    const char *online_user = (const char *)sqlite3_column_text(stmt, 0);
    char buffer[MAX_DATA_LENGTH];
    snprintf(buffer, MAX_DATA_LENGTH, "%s\n", online_user);
    api_send(&state->api, buffer);
  }

  // Close database
  sqlite3_finalize(stmt);
  sqlite3_close(db);
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
      set_online_status(state->user.username, 0);
      state->user.online = 0;
      snprintf(state->user.data, MAX_DATA_LENGTH, YELLOW "Logged out" RESET);
    }
  } else if (strcmp(words[0], "/users") == 0) { // Not implemented
    if (count != 1) // If invalid parameter amount
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: invalid command format");
    else if (state->user.online == 0) { // If not logged in
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: command not currently available");
    } else { // Send online users
      send_online_users(state);
      return 0;
    }

  } else if (strcmp(words[0], "/register") == 0) { // Handle register command
    if (count != 3) { // If invalid parameter amount
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: invalid command format");
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
      state->user.online = add_user(state, words[1], words[2]);
      if (state->user.online == 1) { // If successful, register and login
        api_send(&state->api, state->user.data);
        send_chat_entries(state); // Send all past chats
        return 0;
      }
    }
  } else if (strcmp(words[0], "/login") == 0) { // Handle login command
    if (count != 3) { // If invalid parameter amount
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: invalid command format");
    } else if (state->user.online == 1) { // If already logged in
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: command not currently available");
    } else { // Try login
      state->user.online = authenticate_user(state, words[1], words[2]);
      if (state->user.online == 1) { // If successful, login
        set_online_status(state->user.username, 1);
        api_send(&state->api, state->user.data);
        send_chat_entries(state); // Send all past chats
        return 0;
      }
    }
  } else if (words[0][0] == '/') { // If invalid command
    snprintf(state->user.data, MAX_DATA_LENGTH, "error: unknown command %s", words[0]);
  } else if (words[0][0] == '@') { // If command is private message
    if (count < 2) { // If invalid parameter amount
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: invalid command format");
    } else if (state->user.online) { // Send private message
      if (check_user_exists(state, words[0] + 1)) {
        char notification[MAX_DATA_LENGTH];
        char *word = strtok(buffer, " "); // Separate user and message
        char *rest = strtok(NULL, "");
        char new_msg[sizeof(word) + sizeof(rest) + 1];
        
        snprintf(new_msg, MAX_DATA_LENGTH, "%s %s", remove_start_spaces(word), remove_start_spaces(rest)); // Remove extra spaces
        snprintf(notification, MAX_DATA_LENGTH, "%s\t%s %s: %s", words[0], time, state->user.username, new_msg);
        snprintf(state->user.data, MAX_DATA_LENGTH, "%s %s: %s", time, state->user.username, new_msg);
        add_chat_entry(time, state->user.username, words[0], new_msg); // Save message
        notify_workers(state, notification);
      } else {
        snprintf(state->user.data, MAX_DATA_LENGTH, "error: user not found");
      }
    } else { // If not logged in
      snprintf(state->user.data, MAX_DATA_LENGTH, "error: command not currently available");
    }
  } else { // If command is message
    if (state->user.online) { // If logged in
      snprintf(state->user.data, MAX_DATA_LENGTH, "%s %s: %s", time, state->user.username, remove_start_spaces(buffer));
      add_chat_entry(time, state->user.username, "public", remove_start_spaces(buffer)); // Save message
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
  FD_SET(SSL_get_fd(state->api.ssl), &readfds);
  /* wake on incoming server notifications */
  if (!state->server_eof) FD_SET(state->server_fd, &readfds);
  fdmax = max(SSL_get_fd(state->api.ssl), state->server_fd);

  /* wait for at least one to become ready */
  r = select(fdmax+1, &readfds, NULL, NULL, NULL);
  if (r < 0) {
    if (errno == EINTR) return 0;
    perror("error: select failed");
    return -1;
  }

  /* handle ready file descriptors */
  
  // Wait for at least one to become ready
  r = select(fdmax + 1, &readfds, NULL, NULL, NULL);
  if (r < 0) {
      if (errno == EINTR) return 0;
      perror("error: select failed");
      return -1;
  }

  if (FD_ISSET(SSL_get_fd(state->api.ssl), &readfds)) {
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
static int worker_state_init(struct worker_state *state, SSL *ssl, int server_fd) {

  /* initialize */
  memset(state, 0, sizeof(*state));
  state->server_fd = server_fd;

  /* set up API state */
  api_state_init(&state->api, ssl);

  state->user.online = 0;

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
  close(SSL_get_fd(state->api.ssl));
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
void worker_start(SSL *ssl, int server_fd) {
  struct worker_state state;
  int success = 1;

  /* initialize worker state */
  if (worker_state_init(&state, ssl, server_fd) != 0) {
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
  set_online_status((const char *)&state.user.username, 0);

  worker_state_free(&state);

  exit(success ? 0 : 1);
}