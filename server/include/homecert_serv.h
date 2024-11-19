#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define PASSPHRASE_SIZE 32
#define CLIENT_NAME_SIZE 16
#define KEY_FILE 1000
#define CERT_FILE 2000

/** Resources (fr) :
 * https://www.tala-informatique.fr/index.php?title=C_pipe
 * https://tala-informatique.fr/index.php?title=C_fork
 * http://www.man-linux-magique.net/man2/dup2.html
 * https://www.codequoi.com/manipuler-un-fichier-a-laide-de-son-descripteur-en-c/
*/

struct message_t {
    char passphrase[PASSPHRASE_SIZE + 1];
    char client_name[CLIENT_NAME_SIZE + 1];
};

struct header_t {
    uint16_t file_type;
    uint32_t file_size;
};

// Function prototypes
void get_time(char *buffer, size_t buffer_size);
int is_client_name_safe(const char *client_name);
int generate_request(const char* client_name);
int send_file(SSL *ssl, uint16_t file_type, const char *file_path);
int send_certificate_and_key(SSL *ssl, const char *client_name, const char *base_path);
SSL_CTX *init_ctx(const char *cert_file, const char *key_file);

#endif // SERVER_H