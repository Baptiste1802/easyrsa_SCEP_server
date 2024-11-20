#ifndef HOMECERT_CLIENT_H
#define HOMECERT_CLIENT_H

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#define CLIENT_NAME_SIZE 16
#define PASSPHRASE_SIZE 32
#define KEY_FILE 1000
#define CERT_FILE 2000

struct header_t {
    uint16_t file_type;
    uint32_t file_size;
};

struct message_t {
    char passphrase[PASSPHRASE_SIZE + 1];
    char client_name[CLIENT_NAME_SIZE + 1];
    uint16_t type_id;
};

void get_time(char *buffer, size_t buffer_size);
int is_client_name_safe(const char *client_name);
int prepare_message(struct message_t *message_buffer, const char *passphrase, const char *client_name, uint16_t type_id);   
int receive_file(SSL *ssl, const char *client_name, const char *base_path);
SSL_CTX *init_ctx(void);

#endif // HOMECERT_CLIENT_H
