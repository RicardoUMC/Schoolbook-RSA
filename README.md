# RSA Encryption and Decryption in C

This project implements RSA encryption and decryption using OpenSSL in C. It allows users to generate RSA key pairs, encrypt messages using a public key, and decrypt messages using a private key.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Compilation](#compilation)
- [Usage](#usage)
  - [Generating RSA Keys](#generating-rsa-keys)
  - [Encrypting a Message](#encrypting-a-message)
  - [Decrypting a Message](#decrypting-a-message)
- [Notes](#notes)
- [Troubleshooting](#troubleshooting)

## Prerequisites

To compile and run this program, you need to have OpenSSL installed. You can install it using the following commands:

### Ubuntu/Debian:
```sh
sudo apt update
sudo apt install libssl-dev
```

### macOS (using Homebrew):
```sh
brew install openssl
```

### Windows:
You need to install OpenSSL and ensure that the headers and libraries are correctly linked during compilation.

## Compilation

Use the following command to compile the program:
```sh
gcc schoolbook_rsa.c -o rsa_program -lssl -lcrypto
```

## Usage

Run the program using:
```sh
./rsa_program
```

The program provides a menu with the following options:
1. Generate RSA Keys
2. Encrypt a Message
3. Decrypt a Message
4. Exit

### Generating RSA Keys
When you select option `1`, the program generates a 512-bit RSA key pair and saves them in:
- `rsa_private_key.pem`
- `rsa_public_key.pem`

### Encrypting a Message
1. Select option `2`.
2. Enter the message you want to encrypt.
3. The encrypted message is saved in `encrypted_message.txt`.

### Decrypting a Message
1. Select option `3`.
2. Enter the path to `encrypted_message.txt`.
3. The decrypted message will be displayed in the console.

## Notes
- The encryption uses `RSA_PKCS1_OAEP_PADDING` for better security.
- The keys and encrypted messages are stored in files for later use.
- The program reads and writes keys in PEM format.

## Troubleshooting
If you encounter issues while compiling, make sure:
- OpenSSL is installed and properly linked.
- You are using the correct compiler flags (`-lssl -lcrypto`).

If OpenSSL is installed in a custom location, you may need to specify its include and library paths:
```sh
gcc schoolbook_rsa.c -o rsa_program -I/usr/local/include -L/usr/local/lib -lssl -lcrypto
```
