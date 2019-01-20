#define _POSIX_C_SOURCE 201901L

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct info {
  SSL_CTX *context;
  int clientFD;
  int socketFD;
};

void *handleConnection(void *args) {
  SSL_CTX *context = ((struct info *)args)->context;
  int clientFD = ((struct info *)args)->clientFD;
  int socketFD = ((struct info *)args)->socketFD;
  free(args);

  SSL *connection = SSL_new(context);

  if (connection == NULL) {
    SSL_CTX_free(context);
    close(clientFD);
    close(socketFD);
    fprintf(stderr, "Could not establish TLS connection (null connection)\n");
    exit(EXIT_FAILURE);
  }

  SSL_CTX_free(context);

  if (SSL_set_fd(connection, clientFD) == 0) {
    ERR_clear_error();
    SSL_free(connection);
    close(clientFD);
    close(socketFD);
    fprintf(
        stderr,
        "Could not establish TLS connection (can't set client socket fd)\n");
    exit(EXIT_FAILURE);
  }

  if (SSL_accept(connection) != 1) {
    SSL_free(connection);
    close(clientFD);
    close(socketFD);
    fprintf(stderr, "Could not establish TLS connection (can't accept)\n");
    exit(EXIT_FAILURE);
  }

  char *buffer = malloc(4096);

  // read message
  int numRead = SSL_read(connection, buffer, 4096);

  if (numRead <= 0) {
    switch (SSL_get_error(connection, numRead)) {
      case SSL_ERROR_ZERO_RETURN: {
        // other side gracefully closed, close from our end
        SSL_shutdown(connection);
        SSL_free(connection);
        close(clientFD);
        close(socketFD);
        fprintf(stderr, "Connection unexpectedly closed by client.\n");
        exit(EXIT_FAILURE);
      }
      case SSL_ERROR_WANT_CONNECT:
      case SSL_ERROR_WANT_ACCEPT:
      case SSL_ERROR_WANT_X509_LOOKUP:
      case SSL_ERROR_WANT_CLIENT_HELLO_CB: {
        // non-fatal error, give up anyways
        if (SSL_shutdown(connection) == 0) SSL_shutdown(connection);
        SSL_free(connection);
        close(clientFD);
        close(socketFD);
        fprintf(stderr, "Message not read first try. Giving up.\n");
        exit(EXIT_FAILURE);
      }
      case SSL_ERROR_SYSCALL:
      case SSL_ERROR_SSL:
      default: {
        // fatal error, connection forcefully closes
        SSL_free(connection);
        close(clientFD);
        close(socketFD);
        fprintf(stderr, "Connection broken.\n");
        exit(EXIT_FAILURE);
      }
    }
  }

  buffer[4095] = '\0';

  // write message
  int retVal = SSL_write(connection, buffer, strlen(buffer) + 1);
  if (retVal <= 0) {
    switch (SSL_get_error(connection, retVal)) {
      case SSL_ERROR_ZERO_RETURN: {
        // other side closed their connection gracefully
        SSL_shutdown(connection);
        SSL_free(connection);
        close(clientFD);
        close(socketFD);
        fprintf(stderr, "Client unexpectedly closed connection.\n");
        exit(EXIT_FAILURE);
      }
      case SSL_ERROR_WANT_CONNECT:
      case SSL_ERROR_WANT_ACCEPT:
      case SSL_ERROR_WANT_X509_LOOKUP:
      case SSL_ERROR_WANT_CLIENT_HELLO_CB: {
        // non-fatal error, give up anyways
        if (SSL_shutdown(connection) == 0) SSL_shutdown(connection);
        SSL_free(connection);
        close(clientFD);
        close(socketFD);
        fprintf(stderr, "Message not sent first try. Giving up.\n");
        exit(EXIT_FAILURE);
      }
      case SSL_ERROR_SYSCALL:
      case SSL_ERROR_SSL:
      default: {
        // fatal error, connection forcefully closes
        SSL_free(connection);
        close(clientFD);
        close(socketFD);
        fprintf(stderr, "Connection broken.\n");
        exit(EXIT_FAILURE);
      }
    }
  }

  close(clientFD);
  pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
  if (argc != 1) {
    fprintf(stderr, "Expected no arguments.\n");
    exit(EXIT_FAILURE);
  }

  int socketFD = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (socketFD == -1) {
    fprintf(stderr, "Could not create socket.\n");
    exit(EXIT_FAILURE);
  }

  struct addrinfo *results;
  struct addrinfo hints = {AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE,
                           AF_UNSPEC,
                           SOCK_STREAM,
                           0,
                           0,
                           NULL,
                           NULL,
                           NULL};

  int retVal = getaddrinfo(NULL, "50000", &hints, &results);
  if (retVal != 0) {
    close(socketFD);
    fprintf(stderr, "Could not get address info.\n");
    exit(EXIT_FAILURE);
  } else if (results == NULL) {
    close(socketFD);
    fprintf(stderr, "Could not get address info.\n");
    exit(EXIT_FAILURE);
  }

  for (struct addrinfo *possible = results; possible != NULL;
       possible = possible->ai_next) {
    if (bind(socketFD, possible->ai_addr, sizeof(struct sockaddr)) == 0) {
      break;
    } else {
      int errCode = errno;
      if (errCode == EACCES || errCode == EBADFD || errCode == EINVAL ||
          errCode == ENOTSOCK || errCode == EFAULT || errCode == ELOOP ||
          errCode == ENOENT || errCode == ENOMEM || errCode == ENOTDIR ||
          errCode == EROFS) {
        // fatal error, stop and report error.
        freeaddrinfo(results);
        close(socketFD);
        fprintf(stderr, "Could not bind socket.\n");
        exit(EXIT_FAILURE);
      } else {
        // connection failed
        if (possible->ai_next == NULL) {
          freeaddrinfo(results);
          close(socketFD);
          fprintf(stderr, "Could not bind any candidate sockets.\n");
          exit(EXIT_FAILURE);
        }
      }
    }
  }

  freeaddrinfo(results);

  if (listen(socketFD, 4) != 0) {
    close(socketFD);
    fprintf(stderr, "Could not listen on candidate socket.\n");
    exit(EXIT_FAILURE);
  }

  SSL_CTX *context = SSL_CTX_new(TLS_server_method());
  if (context == NULL) {
    close(socketFD);
    fprintf(stderr, "Could not create context\n");
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_certificate_file(context, "certificate.pem",
                                   SSL_FILETYPE_PEM) != 1) {
    ERR_clear_error();
    close(socketFD);
    SSL_CTX_free(context);
    fprintf(stderr, "Could not load certificate\n");
    exit(EXIT_FAILURE);
  }
  if (SSL_CTX_use_PrivateKey_file(context, "privatekey.pem",
                                  SSL_FILETYPE_PEM) != 1) {
    ERR_clear_error();
    close(socketFD);
    SSL_CTX_free(context);
    fprintf(stderr, "Could not load private key\n");
    exit(EXIT_FAILURE);
  }

  while (true) {
    int clientFD = accept(socketFD, NULL, NULL);
    if (clientFD < 0) {
      SSL_CTX_free(context);
      close(socketFD);
      fprintf(stderr, "Could not accept client connection.\n");
      exit(EXIT_FAILURE);
    }

    struct info *args = malloc(sizeof(struct info));
    args->context = context;
    args->clientFD = clientFD;
    args->socketFD = socketFD;

    pthread_t thread;
    pthread_create(&thread, NULL, handleConnection, args);
  }

  exit(EXIT_SUCCESS);
}