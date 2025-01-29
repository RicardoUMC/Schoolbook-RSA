#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>

// Función para generar el par de llaves RSA y almacenarlas en archivos
void generate_rsa_keys() {
    int bits = 512;
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);

    if (!RSA_generate_key_ex(rsa, bits, e, NULL)) {
        fprintf(stderr, "Error generating RSA keys.\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    // Guardar la clave privada en formato base64
    FILE *priv_file = fopen("rsa_private_key.pem", "w");
    if (!priv_file) {
        perror("Error opening private key file");
        RSA_free(rsa);
        BN_free(e);
        return;
    }
    PEM_write_RSAPrivateKey(priv_file, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(priv_file);

    // Guardar la clave pública en formato base64
    FILE *pub_file = fopen("rsa_public_key.pem", "w");
    if (!pub_file) {
        perror("Error opening public key file");
        RSA_free(rsa);
        BN_free(e);
        return;
    }
    PEM_write_RSA_PUBKEY(pub_file, rsa);
    fclose(pub_file);

    printf("RSA key pair generated and saved to rsa_private_key.pem and rsa_public_key.pem\n");

    RSA_free(rsa);
    BN_free(e);
}

// Función para cifrar un mensaje con RSA y una clave pública
void rsa_encrypt(const char *message, const char *pubkey_file) {
    FILE *pub_file = fopen(pubkey_file, "r");
    if (!pub_file) {
        perror("Error opening public key file");
        return;
    }

    RSA *rsa = PEM_read_RSA_PUBKEY(pub_file, NULL, NULL, NULL);
    fclose(pub_file);
    if (!rsa) {
        fprintf(stderr, "Error reading public key.\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    int rsa_size = RSA_size(rsa);
    unsigned char *encrypted = malloc(rsa_size);

    int encrypted_length = RSA_public_encrypt(strlen(message), (unsigned char *)message, encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    if (encrypted_length == -1) {
        fprintf(stderr, "Error encrypting message.\n");
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        free(encrypted);
        return;
    }

    // Convertir a base64 y guardar en archivo
    FILE *enc_file = fopen("encrypted_message.txt", "w");
    if (!enc_file) {
        perror("Error opening encrypted file");
        RSA_free(rsa);
        free(encrypted);
        return;
    }

    BIO *bio = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_write(bio, encrypted, encrypted_length);
    BIO_flush(bio);

    BUF_MEM *buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    fwrite(buffer_ptr->data, 1, buffer_ptr->length, enc_file);

    BIO_free_all(bio);
    fclose(enc_file);
    free(encrypted);

    printf("Message encrypted and saved to encrypted_message.txt\n");

    RSA_free(rsa);
}

// Función para descifrar un mensaje con RSA y una clave privada
void rsa_decrypt(const char *enc_file, const char *privkey_file) {
    FILE *priv_file = fopen(privkey_file, "r");
    if (!priv_file) {
        perror("Error opening private key file");
        return;
    }

    RSA *rsa = PEM_read_RSAPrivateKey(priv_file, NULL, NULL, NULL);
    fclose(priv_file);
    if (!rsa) {
        fprintf(stderr, "Error reading private key.\n");
        ERR_print_errors_fp(stderr);
        return;
    }

    FILE *file = fopen(enc_file, "r");
    if (!file) {
        perror("Error opening encrypted file");
        RSA_free(rsa);
        return;
    }

    // Leer base64 y decodificar
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *encoded = malloc(file_size + 1);
    fread(encoded, 1, file_size, file);
    fclose(file);
    encoded[file_size] = '\0';

    BIO *bio = BIO_new_mem_buf(encoded, -1);
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    unsigned char *encrypted = malloc(RSA_size(rsa));
    int encrypted_length = BIO_read(bio, encrypted, RSA_size(rsa));
    BIO_free_all(bio);
    free(encoded);

    if (encrypted_length <= 0) {
        fprintf(stderr, "Error decoding base64 encrypted message.\n");
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        free(encrypted);
        return;
    }

    unsigned char *decrypted = malloc(RSA_size(rsa));
    int decrypted_length = RSA_private_decrypt(encrypted_length, encrypted, decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    if (decrypted_length == -1) {
        fprintf(stderr, "Error decrypting message.\n");
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        free(encrypted);
        free(decrypted);
        return;
    }

    printf("Decrypted message: %.*s\n", decrypted_length, decrypted);

    RSA_free(rsa);
    free(encrypted);
    free(decrypted);
}

// Función principal con menú para el usuario
int main() {
    int option;
    char message[256];
    char filepath[256];

    while (1) {
        printf("\nMenu:\n");
        printf("1. Generate RSA Keys\n");
        printf("2. Encrypt a Message\n");
        printf("3. Decrypt a Message\n");
        printf("4. Exit\n");
        printf("Select an option: ");
        scanf("%d", &option);
        getchar();  // Limpiar el buffer de entrada

        switch (option) {
            case 1:
                generate_rsa_keys();
                break;
            case 2:
                printf("Enter the message to encrypt: ");
                fgets(message, sizeof(message), stdin);
                message[strcspn(message, "\n")] = '\0';
                rsa_encrypt(message, "rsa_public_key.pem");
                break;
            case 3:
                printf("Enter the encrypted file path: ");
                fgets(filepath, sizeof(filepath), stdin);
                filepath[strcspn(filepath, "\n")] = '\0';
                rsa_decrypt(filepath, "rsa_private_key.pem");
                break;
            case 4:
                printf("Exiting program.\n");
                return 0;
            default:
                printf("Invalid option. Please select again.\n");
                break;
        }
    }
}

