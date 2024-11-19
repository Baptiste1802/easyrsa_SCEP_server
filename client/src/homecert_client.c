#include "homecert_client.h"

void get_time(char *buffer, size_t buffer_size) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);

    strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", tm_info);
}

int is_client_name_safe(const char *client_name){

    if (strlen(client_name) > CLIENT_NAME_SIZE) {
        char date_buffer[20];
        get_time(date_buffer, sizeof(date_buffer));
        fprintf(stderr, "[%s] nom client trop long : %s\n", date_buffer, client_name);
        return 0;
    }

    for (size_t i = 0; i < strlen(client_name); i++) {
        if (!isalpha((unsigned char)client_name[i]) && !isdigit((unsigned char)client_name[i])) {
            char date_buffer[20];
            get_time(date_buffer, sizeof(date_buffer));
            fprintf(stderr, "[%s] nom client invalide : %s\n", date_buffer, client_name);
            return 0; 
        }
    }

    return 1;
}

int prepare_message(struct message_t *message_buffer, const char *passphrase, const char *client_name){

    strncpy(message_buffer->passphrase, passphrase, PASSPHRASE_SIZE);
    strncpy(message_buffer->client_name, client_name, CLIENT_NAME_SIZE);
    message_buffer->passphrase[PASSPHRASE_SIZE] = '\0';
    message_buffer->client_name[CLIENT_NAME_SIZE] = '\0';

    return 0;
}

int receive_file(SSL *ssl, const char *client_name, const char *base_path   ) {
    struct header_t header;
    FILE *file;
    char file_path[512];
    ssize_t bytes_received;

    // Lire l'en-tête du fichier
    if (SSL_read(ssl, &header, sizeof(header)) <= 0) {
        fprintf(stderr, "SSL_read() header failed\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    printf("Type de fichier : %u, Taille du fichier : %u\n", header.file_type, header.file_size);


    printf("file_path %s\n", file_path);

    // Déterminer le type de fichier et construire le chemin de destination
    switch (header.file_type) {
        case KEY_FILE:
            printf("Réception d'un fichier clé.\n");
            snprintf(file_path, sizeof(file_path), "%s/%s_pki.key", base_path, client_name);
            break;

        case CERT_FILE:
            printf("Réception d'un fichier certificat.\n");
            snprintf(file_path, sizeof(file_path), "%s/%s_pki.cert", base_path, client_name);
            break;

        default:
            fprintf(stderr, "Type de fichier inconnu : %u\n", header.file_type);
            return -1;
    }


    printf("file_path %s\n", file_path);

    // Ouvrir le fichier pour l'écriture
    file = fopen(file_path, "wb");
    if (!file) {
        perror("Erreur d'ouverture du fichier");
        return -1;
    }

    char buffer[1024];
    size_t remaining_size = header.file_size;

    printf("Début de la réception du fichier...\n");

    // Réception du fichier
    while (remaining_size > 0) {
        bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_received <= 0) {
            fprintf(stderr, "SSL_read() erreur lors de la réception du fichier\n");
            ERR_print_errors_fp(stderr);
            fclose(file);
            return -1;
        }

        // Calculer combien de données écrire (au cas où la réception serait plus grande que les données restantes)
        size_t to_write = (bytes_received > remaining_size) ? remaining_size : bytes_received;

        // Écrire dans le fichier
        if (fwrite(buffer, 1, to_write, file) != to_write) {
            perror("Erreur d'écriture dans le fichier");
            fclose(file);
            return -1;
        }

        remaining_size -= to_write;

        printf("Reçu %zu octets, reste %zu octets à recevoir\n", to_write, remaining_size);
    }

    printf("Réception terminée\n");

    fclose(file);

    return 0;
}


SSL_CTX *init_ctx(){
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    method = TLS_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        puts("SSL_CTX_new failed\n");
        exit(1);
    }

    return ctx;
}

int main(int argc, char const *argv[]) {
    int client_fd;
    struct sockaddr_in server_extremity;
    char buffer[2048];
    char passphrase[PASSPHRASE_SIZE+1];
    char client_name[CLIENT_NAME_SIZE+1];

    printf("Entrez la passphrase : ");
    if (fgets(passphrase, sizeof(passphrase), stdin) == NULL) {
        perror("Erreur lors de la lecture de l'entrée");
        return 1;
    }
    passphrase[strcspn(passphrase, "\n")] = 0;


    printf("Entrez le nom du client : ");
    if (fgets(client_name, sizeof(client_name), stdin) == NULL) {
        perror("Erreur lors de la lecture de l'entrée");
        return 1;
    }
    client_name[strcspn(client_name, "\n")] = 0;

    if (is_client_name_safe(client_name) == 0){
        printf("salade\n");
        exit(1);
    }

    struct message_t message_buffer;

    prepare_message(&message_buffer, passphrase, client_name);

    SSL *ssl;
    SSL_CTX *ctx;
    ctx = init_ctx();
    
    const char *server_ip = "127.0.0.1";
    int server_port = 666;

    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket()");
        exit(errno);
    }

    memset(&server_extremity, 0, sizeof(server_extremity));
    server_extremity.sin_family = AF_INET;
    server_extremity.sin_port = htons(server_port);

    if (inet_pton(AF_INET, server_ip, &server_extremity.sin_addr) <= 0) {
        perror("inet_pton()");
        exit(errno);
    }

    if (connect(client_fd, (struct sockaddr *)&server_extremity, sizeof(server_extremity)) == -1) {
        perror("connect()");
        exit(errno);
    }

    printf("Connecté au serveur %s:%d\n", server_ip, server_port);

    ssl = SSL_new(ctx);
    if (!ssl) {
        puts("SSL_new() failed\n");
        exit(1);
    }

    SSL_set_fd(ssl, client_fd);

    if (SSL_connect(ssl) != 1) {
        puts("SSL_connect() failed");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    printf("TLS connecté avec succès\n");

    // Boucle pour envoyer et recevoir des messages
    while (1) {

        // Envoi du message au serveur via SSL
        if (SSL_write(ssl, &message_buffer, sizeof(struct message_t)) <= 0) {
            fprintf(stderr, "Erreur lors de l'envoi des données: ");
            ERR_print_errors_fp(stderr);
            break;
        }

        // Réception du premier fichier
        if (receive_file(ssl, client_name, "/home/baptiste/Documents/PKI/new") != 0) {
            fprintf(stderr, "Erreur lors de la réception du premier fichier\n");
            break;  // Sortir de la boucle si l'envoi échoue
        }

        // Réception du deuxième fichier
        if (receive_file(ssl, client_name, "/home/baptiste/Documents/PKI/new") != 0) {
            fprintf(stderr, "Erreur lors de la réception du deuxième fichier\n");
            break;  // Sortir de la boucle si l'envoi échoue
        }

        break; // Arrêt de la boucle après une première interaction
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    // Fermeture de la connexion
    close(client_fd);
    return 0;
}
