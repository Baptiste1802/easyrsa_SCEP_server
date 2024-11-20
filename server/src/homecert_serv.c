#include "homecert_serv.h"

void get_time(char *buffer, size_t buffer_size) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);

    strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", tm_info);
}

int is_client_name_safe(const char *client_name){

    for (size_t i = 0; i < strlen(client_name); i++) {
        if (!isalpha((unsigned char)client_name[i]) && !isdigit((unsigned char)client_name[i])) {
            fprintf(stderr, "is_client_name_safe()nom client invalide : %s\n", client_name);
            return 0; 
        }
    }

    return 1;
}

int execute_command(const char *bin_path, char *const args[], const char *inputs[], size_t num_inputs){
    int pipefd[2]; // contains fd used to write into and read from the pipe 

    if (pipe(pipefd) == -1) {
        fprintf(stderr, "pipe() failed creating pipe : %s\n", strerror(errno));
        return -1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        fprintf(stderr, "fork() Failed creating the child process %s\n", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) { // pid == 0 -> child processus
        close(pipefd[1]);

        // duplicate the pipe reader fd into STDIN_FILENO
        if (dup2(pipefd[0], STDIN_FILENO) == -1) {
            fprintf(stderr, "dup2() failed: %s\n", strerror(errno));
            close(pipefd[0]);
            _exit(EXIT_FAILURE);  // exit child processus
        }
        close(pipefd[0]); // no longer needed bcs STDIN_FILENO points to it

        // execute the command
        if (execve(bin_path, args, NULL) == -1) {
            fprintf(stderr, "execve() failed: %s\n", strerror(errno));
            _exit(EXIT_FAILURE);
        }
    } else {  // pid > 0 -> parent processus
        close(pipefd[0]); // useless

        // Écrire les entrées une par une
        for (size_t i = 0; i < num_inputs; i++) {
            if (write(pipefd[1], inputs[i], strlen(inputs[i])) == -1) { // redirected to child STDIN
                // TODO verify size of written octets == sizeof(client_name)
                fprintf(stderr, "write() failed: %s\n", strerror(errno));
                close(pipefd[1]);
                return -1;
            }
            if (write(pipefd[1], "\n", 1) == -1) { // close the entry
                fprintf(stderr, "write() failed: %s\n", strerror(errno));
                close(pipefd[1]);
                return -1;
            }
        }

        close(pipefd[1]); // no longer needed

        int status;

        if (waitpid(pid, &status, 0) == -1) { // wait the child process to end
            fprintf(stderr, "waitpid() failed trying to wait the child process : %s\n", strerror(errno));
            return -1;
        }

        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 0) {
                fprintf(stdout, "Command successfuly executed\n");
                return 0;
            } else {
                fprintf(stderr, "Child processus ended with status code : %d\n", WEXITSTATUS(status));
            }
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr, "Child processus ended with status code : : %d\n", WTERMSIG(status));
        } else {
            fprintf(stderr, "Child processus we don't know how..\n");
        }
        return -1;
    }
}

int generate_request(const char *client_name){
    
    // command args
    char *const args[] = {
        "easyrsa",
        "gen-req",
        (char *) client_name,
        "nopass",
        NULL // tab must end with NULL
    };

    const char *inputs[] = {client_name};

    return execute_command("/usr/bin/easyrsa", args, inputs, 1);

}

int sign_request(const char *client_name, const int type_id, const char *passphrase){
    

    const char *type = (type_id == 1) ? "server" : "client";

    // command args
    char *const args[] = {
        "easyrsa",
        "sign-req",
        (char *)type,
        (char *)client_name,
        NULL
    };

    // Inputs
    const char *inputs[] = {
        "yes",
        (char *) passphrase
    };

    return execute_command("./easyrsa_modified", args, inputs, 2);
}


int send_file(SSL *ssl, uint16_t file_type, const char *file_path){
    // TODO refactor code

    FILE *file;
    struct stat file_stat;

    file = fopen(file_path, "rb");
    if (!file) {
        fprintf(stderr, "fopen() failed opening %s : %s\n", file_path, strerror(errno));
        return -1;
    }

    struct header_t header;
    memset(&header, 0, sizeof(header));
    header.file_type = file_type;

    int fd = fileno(file); // get the file fd
    if (fd == -1) {
        fprintf(stderr, "fileno() failed retrieving file fd : %s\n", strerror(errno));
        return -1;
    }

    if (fstat(fd, &file_stat) < 0) { // get file's stats
        fprintf(stderr, "fstat() failed getting stats on fd %d : %s\n", fd, strerror(errno));
        return -1;
    }

    // set the file size into the header msg
    header.file_size = (uint32_t) file_stat.st_size;

    // send it
    if (SSL_write(ssl, &header, sizeof(header)) <= 0) { 
        fprintf(stderr, "SSL_write() sending header : %s\n", strerror(errno));
        fclose(file);
        return -1;
    }

    // send the file
    char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) { // todo verify fread didn't fail
        if (SSL_write(ssl, buffer, bytes_read) <= 0) {
            fprintf(stderr, "SSL_write() sending file : %s\n", strerror(errno));
            fclose(file);
            return -1;
        }
    }

    if (ferror(file)) {
        fprintf(stderr, "ferror() : %s\n", strerror(errno));
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}

int send_certificate_and_key(SSL *ssl, const char *client_name, const char *base_path) {
    char buffer[1024];
    size_t bytes_read;

    char cert_path[512];
    char key_path[512];

    snprintf(cert_path, sizeof(cert_path), "%s/issued/%s.crt", base_path, client_name);
    snprintf(key_path, sizeof(key_path), "%s/private/%s.key", base_path, client_name);

    if (send_file(ssl, (uint16_t) CERT_FILE, cert_path) == -1){
        fprintf(stderr, "send_file() failed sending cert_file");
        return -1;
    }
    if (send_file(ssl, (uint16_t) KEY_FILE, key_path) == -1){
        fprintf(stderr, "send_file() failed sending key_file");
        return -1;
    }

    return 0;
}

SSL_CTX *init_ctx(const char *cert_file, const char *key_file){

    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "SSL_CTX_use_certificate_file() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "SSL_CTX_use_PrivateKey_file() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "SSL_CTX_check_private_key() failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    return ctx;
}


int main(int argc, char const *argv[]){
        
    // TODO secure auth
    const char *passphrase = "azerty"; // CA passphrase
    
    int server_fd, client_fd, working;
    char buffer[2048];
    char date_buffer[20];

    struct sockaddr_in self_extremity, client_extremity;
    int addr_size = sizeof(client_extremity); 
    ssize_t bytes_received;
    struct message_t received_message;

    SSL_CTX *ctx;
    SSL *ssl;

    // TODO pass through command line
    const char *base_path = "./pki";
    const char *cert_file = "./pki/issued/server.crt";
    const char *key_file = "./pki/private/server.key";

    ctx = init_ctx(cert_file, key_file);

    memset(&client_extremity, 0, sizeof(client_extremity)); 
    memset(&self_extremity, 0, sizeof(self_extremity));
    self_extremity.sin_family = AF_INET;
    self_extremity.sin_port = htons(6666);

    if (inet_pton(AF_INET, "127.0.0.1", &self_extremity.sin_addr) == -1){
        fprintf(stderr, "inet_pton() : %s\n", strerror(errno));
        exit(errno);
    }

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        fprintf(stderr, "socket() : %s\n", strerror(errno));
        exit(errno);
    }

    // TODO ask the extremity in conf file or take the first one that is not localhost 
    if (bind(server_fd, (struct sockaddr*) &self_extremity, sizeof(self_extremity)) == -1){
        fprintf(stderr, "bind() : %s\n", strerror(errno));
        exit(errno);
    }

    if (listen(server_fd, 5) == -1){
        fprintf(stderr, "listen() : %s\n", strerror(errno));
        exit(errno);
    }

    while (1){

        if ((client_fd = accept(server_fd, (struct sockaddr*) &client_extremity, &addr_size)) == -1){
            fprintf(stderr, "accept() : %s\n", strerror(errno));
            continue;
        }

        fprintf(stdout, "Client connected : %s\n", inet_ntoa(client_extremity.sin_addr));

        ssl = SSL_new(ctx);
        if (!ssl) {
            fprintf(stderr, "SSL_new() failed\n");
            ERR_print_errors_fp(stderr);
            close(client_fd);
            continue;
        }

        if (SSL_set_fd(ssl, client_fd) == 0) {
            fprintf(stderr, "SSL_set_fd() failed\n");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        if (SSL_accept(ssl) <= 0) {
            fprintf(stderr, "SSL_accept() failed\n");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        // fprintf(stdout, "TLS connection established\n");

        while (1){

            // waiting request from the client

            // TODO gestion d'erreur SSL_read avec code d'erreur SSL
            bytes_received = SSL_read(ssl, &received_message, sizeof(received_message));
            if (bytes_received <= 0) {
                if (bytes_received == 0) {
                    fprintf(stdout, "Client disconnected\n");
                } else {
                    fprintf(stderr, "SSL_read() failed");
                }
                break;
            }

            if (strncmp(passphrase, received_message.passphrase, strlen(passphrase)) != 0) {
                get_time(date_buffer, sizeof(date_buffer));
                fprintf(stderr, "[%s] pass failed %s for client_name %s\n", date_buffer, received_message.passphrase, received_message.client_name);
                // TODO send error msg
                break;
            }

            if (generate_request(received_message.client_name) == -1){
                get_time(date_buffer, sizeof(date_buffer));
                fprintf(stderr, "[%s] failed generating cert request for client_name %s\n", date_buffer, received_message.client_name);
                // TODO send error msg
                break;
            }

            if (sign_request(received_message.client_name, received_message.type_id, passphrase) == -1){
                get_time(date_buffer, sizeof(date_buffer));
                fprintf(stderr, "[%s] failed signing cert request for client_name %s\n", date_buffer, received_message.client_name);
                // TODO send error msg
                break;
            }

            if (send_certificate_and_key(ssl, received_message.client_name, base_path) == -1){
                get_time(date_buffer, sizeof(date_buffer));
                fprintf(stderr, "[%s] failed sending certs for client_name %s\n", date_buffer, received_message.client_name);
                // TODO send error msg
                break;
            }

            break;

        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);

    }

    close(server_fd);
    SSL_CTX_free(ctx);

    return 0;
}
