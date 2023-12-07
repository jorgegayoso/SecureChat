#ifndef _API_H_
#define _API_H_

#include <openssl/ssl.h>
#include <openssl/err.h>

struct api_msg {
  char *data;
  size_t length;
};

struct api_state {
  SSL *ssl;
};


int api_recv(struct api_state *state, struct api_msg *msg);
void api_recv_free(struct api_msg *msg);

void api_state_free(struct api_state *state);
void api_state_init(struct api_state *state, SSL *ssl);

int api_send(struct api_state *state, const char *message);

#endif /* defined(_API_H_) */
