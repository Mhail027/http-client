#ifndef _HELPER_
#define _HELPER_

#include <errno.h>
#include "parson.h"

#define BUFLEN 4096
#define LINELEN 1000

#define HEADER_TERMINATOR "\r\n\r\n"
#define HEADER_TERMINATOR_SIZE (sizeof(HEADER_TERMINATOR) - 1)
#define CONTENT_LENGTH "Content-Length: "
#define CONTENT_LENGTH_SIZE (sizeof(CONTENT_LENGTH) - 1)

#define SIZE_T_MAX ((size_t)-1)

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
char *basic_extract_json_response(const char *const str);

/* Extract and returns the value of a field from a HTTP response. */
char *extract_from_http_response(const char *const response,
	const char *const field
);

/* Get a string value of a field from a json string. */
char *get_string_from_json_string(char* json_string, char *field_name);

/* Get a number value of a field from a json string. */
double get_number_from_json_string(char* json_string, char *field_name);

/* Read a line from stdin and remove the new line character. */
void read_line(char *const buff, const int len);

/* Put the code of the server's response at the address of the second
 * parameter. */
void get_http_response_code(const char *const response, char *const code);

/****
 * Print the value of the error/message field from json's payload 
 * of an http response.
 * @return: 2 => response payload has a field named message
 *			4 => response payload has a field named error
 *			-1 => else
 ****/
int basic_print_http_response_with_content(char *const response);

/* Print a message corresonding with the http code of the response. */
int basic_print_http_response(
	char *const response, const char *const success_msg
);

/* Get the json value from a string. If can not do this, stop
 * the program. */
JSON_Value *get_json_val_from_string(const char *const response);

/* Get an array from a json value. The array is found at the given
 * field. If can not do this, stop the program. */
JSON_Array *get_json_array_from_json_val(
	JSON_Value *value, const char *const field_name
);

/* Make the json string more readable. */
char *get_pretty_string_from_json_string(const char *string);

/* Convert a string to size_t. If a problem occurs, return SIZE_T_MAX. */
size_t atos(const char *const string);

#endif
