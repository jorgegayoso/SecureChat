#ifndef _SERVER_H_
#define _SERVER_H_

// Server settings
#define MAX_CHILDREN 16

// Worker settings
#define MAX_DATA_LENGTH 256

#define MIN_PASS_LENGTH 0

#define MAX_USER_LENGTH 16
#define MAX_PASS_LENGTH 64

#define CERT_FILE "serverkeys/X509_Certificate.crt"
#define KEY_FILE "serverkeys/X509_Key.key"

#endif /* defined(_SERVER_H_) */
