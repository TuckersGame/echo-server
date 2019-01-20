#define _POSIX_C_SOURCE 201901L

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(
        stderr,
        "Expected two arguments: server to connect to, and string to send.\n");
    exit(EXIT_FAILURE);
  }

  int const MESSAGE_LENGTH = strlen(argv[2]) + 1;

  int socketFD = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (socketFD == -1) {
    fprintf(stderr, "Could not create socket.\n");
    exit(EXIT_FAILURE);
  }

  struct addrinfo *results;
  struct addrinfo hints = {AI_ADDRCONFIG | AI_NUMERICSERV,
                           AF_INET,
                           SOCK_STREAM,
                           0,
                           0,
                           NULL,
                           NULL,
                           NULL};

  int retVal = getaddrinfo(argv[1], "50000", &hints, &results);
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
    if (connect(socketFD, possible->ai_addr, sizeof(struct sockaddr)) == 0) {
      break;
    } else if (!(errno == ECONNREFUSED || errno == ENETUNREACH ||
                 errno == ETIMEDOUT)) {
      // fatal error, stop and report error.
      freeaddrinfo(results);
      close(socketFD);
      fprintf(stderr, "Could not connect.");
      exit(EXIT_FAILURE);
    } else {
      // connection failed
      if (possible->ai_next == NULL) {
        freeaddrinfo(results);
        close(socketFD);
        fprintf(stderr, "Could not connect to any candidate address.\n");
        exit(EXIT_FAILURE);
      }
    }
  }

  freeaddrinfo(results);

  // have TCP connection, establishing SSL connection
  SSL_CTX *context = SSL_CTX_new(TLS_client_method());
  if (context == NULL) {
    close(socketFD);
    fprintf(stderr, "Could not establish TLS connection.\n");
    exit(EXIT_FAILURE);
  }

  SSL *connection = SSL_new(context);
  SSL_CTX_free(context);
  if (connection == NULL) {
    close(socketFD);
    fprintf(stderr, "Could not establish TLS connection.\n");
    exit(EXIT_FAILURE);
  }

  if (SSL_set_fd(connection, socketFD) == 0) {
    ERR_clear_error();
    close(socketFD);
    fprintf(stderr, "Could not establish TLS connection.\n");
    exit(EXIT_FAILURE);
  }

  if (SSL_connect(connection) != 1) {
    ERR_clear_error();
    close(socketFD);
    fprintf(stderr, "Could not establish TLS connection.\n");
    exit(EXIT_FAILURE);
  }

  // write message
  retVal = SSL_write(connection, argv[2], MESSAGE_LENGTH);
  if (retVal <= 0) {
    switch (SSL_get_error(connection, retVal)) {
      case SSL_ERROR_ZERO_RETURN: {
        // other side closed their connection gracefully
        SSL_shutdown(connection);
        SSL_free(connection);
        close(socketFD);
        fprintf(stderr, "Server unexpectedly closed connection.\n");
        exit(EXIT_FAILURE);
      }
      case SSL_ERROR_WANT_CONNECT:
      case SSL_ERROR_WANT_ACCEPT:
      case SSL_ERROR_WANT_X509_LOOKUP:
      case SSL_ERROR_WANT_CLIENT_HELLO_CB: {
        // non-fatal error, give up anyways
        if (SSL_shutdown(connection) == 0) SSL_shutdown(connection);
        SSL_free(connection);
        close(socketFD);
        fprintf(stderr, "Message not sent first try. Giving up.\n");
        exit(EXIT_FAILURE);
      }
      case SSL_ERROR_SYSCALL:
      case SSL_ERROR_SSL:
      default: {
        // fatal error, connection forcefully closes
        SSL_free(connection);
        close(socketFD);
        fprintf(stderr, "Connection broken.\n");
        exit(EXIT_FAILURE);
      }
    }
  }

  char *buffer = malloc(MESSAGE_LENGTH);

  // read message
  int numRead = SSL_read(connection, buffer, MESSAGE_LENGTH);

  if (numRead <= 0) {
    switch (SSL_get_error(connection, numRead)) {
      case SSL_ERROR_ZERO_RETURN: {
        // other side gracefully closed, close from our end
        SSL_shutdown(connection);
        SSL_free(connection);
        close(socketFD);
        fprintf(stderr, "Connection unexpectedly closed by server.\n");
        exit(EXIT_FAILURE);
      }
      case SSL_ERROR_WANT_CONNECT:
      case SSL_ERROR_WANT_ACCEPT:
      case SSL_ERROR_WANT_X509_LOOKUP:
      case SSL_ERROR_WANT_CLIENT_HELLO_CB: {
        // non-fatal error, give up anyways
        if (SSL_shutdown(connection) == 0) SSL_shutdown(connection);
        SSL_free(connection);
        close(socketFD);
        fprintf(stderr, "Message not read first try. Giving up.\n");
        exit(EXIT_FAILURE);
      }
      case SSL_ERROR_SYSCALL:
      case SSL_ERROR_SSL:
      default: {
        // fatal error, connection forcefully closes
        SSL_free(connection);
        close(socketFD);
        fprintf(stderr, "Connection broken.\n");
        exit(EXIT_FAILURE);
      }
    }
  }

  // good, print
  fprintf(stdout, "%s", buffer);
  if (SSL_shutdown(connection) == 0) SSL_shutdown(connection);
  SSL_free(connection);
  close(socketFD);
  exit(EXIT_SUCCESS);
}