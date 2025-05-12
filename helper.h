#ifndef _HELPER_
#define _HELPER_

#include <errno.h>

#define BUFLEN 4096
#define LINELEN 1000

#define HEADER_TERMINATOR "\r\n\r\n"
#define HEADER_TERMINATOR_SIZE (sizeof(HEADER_TERMINATOR) - 1)
#define CONTENT_LENGTH "Content-Length: "
#define CONTENT_LENGTH_SIZE (sizeof(CONTENT_LENGTH) - 1)

#define DIE(assertion, call_description)                                      \
	do {                                                                      \
		if (assertion) {                                                      \
			fprintf(stderr, "(%s, %d): ", __FILE__, __LINE__);                \
			perror(call_description);                                         \
			exit(errno);                                                      \
		}                                                                     \
	} while (0)

/* Adds a line to a string message. */
void compute_message(char *message, const char *line);

/* opens a connection with server host_ip on port portno, returns a socket. */
int open_connection(char *host_ip, int portno, int ip_type, int socket_type,
                    int flag);

/* closes a server connection on socket sockfd. */
void close_connection(int sockfd);

/* Send a message to a server. */
void send_to_server(int sockfd, char *message);

/* Receives and returns the message from a server. */
char *receive_from_server(int sockfd);

/* Extracts and returns a JSON from a server response. */
char *basic_extract_json_response(char *str);

/* Extract and returns the value of a field from a HTTP
 * response. The given string are not modified. */
char *extract_from_http_response(const char *const response, char *field);

/* Extract and returns the value of a field from a JSON
 * response. The given string are not modified. 
 *
 * !!! Fields must start and end with " character. */
char *extract_from_json_response(char* response, char *field);

/* Read a line from stdin and remove the new line character. */
void read_line(char *buff, int len);

/****
 * Print the value of the error/message field from json's payload 
 * of an http response.
 * @return: 0 => response payload has a field named error or message
 *			-1 => else
 */
int basic_print_http_response_with_content(char *const response);

/* Print a message corresonding with the http code of the response. */
void print_http_response(char *const response, const char *const success_msg);

#endif
