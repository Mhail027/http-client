#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helper.h"
#include "requests.h"

static void add_host(char *message, char *ip, int port, char *line)
{
	int ret;

	ret = sprintf(line, "Host: %s:%d", ip, port);
	DIE(ret < 0, "sprintf() failed\n");
	compute_message(message, line);
}

static void add_cookie(char *message, char *cookie, char *line)
{
	int ret;

	if (cookie) {
		ret = sprintf(line, "Cookie: %s", cookie);
		DIE(ret < 0, "sprintf() failed\n");
    	compute_message(message, line);
	}
}

static void add_token(char *message, char *token, char *line)
{
	int ret;

	if (token) {
		ret = sprintf(line, "Authorization: Bearer %s", token);
		DIE(ret < 0, "sprintf() failed\n");
    	compute_message(message, line);
	}
}

static void add_content_type(char *message, char *content_type, char *line)
{
	int ret;

	ret = sprintf(line, "Content-Type: %s", content_type);
	DIE(ret < 0, "sprintf() failed\n");
    compute_message(message, line);
}

static void add_content_length(char *message, unsigned long len, char *line)
{
	int ret;

	ret = sprintf(line, "Content-Length: %lu", len);
	DIE(ret < 0, "sprintf() failed\n");
    compute_message(message, line);
}

static char *compute_basic_request(char *method, char *ip, int port,
								   char *url, char *cookie, char *token)
{
	char *message = calloc(BUFLEN, sizeof(char));
	char *line = calloc(LINELEN, sizeof(char));
	int ret;

	/* Write the method name, URL and protocol type. */
	ret = sprintf(line, "%s %s HTTP/1.1", method, url);
	DIE(ret < 0, "sprintf() failed\n");
	compute_message(message, line);
	
	/* Add the host, cookie and token. */
	add_host(message, ip, port, line);
	add_cookie(message, cookie, line);
	add_token(message, token, line);

	/* Close connection after this message. */
    compute_message(message, "Connection: close");

	/* Add new line at end of header */
	compute_message(message, "");

	memset(line, 0, LINELEN);
	free(line);
	return message;
}

static char *compute_content_request(char *method, char *ip, int port,
				char *url, char* content_type, char *content, char *cookie,
				char *token)
{
	char *message = calloc(BUFLEN, sizeof(char));
	char *line = calloc(LINELEN, sizeof(char));
	int ret;

	/* Write the method name, URL and protocol type. */
	ret = sprintf(line, "%s %s HTTP/1.1", method, url);
	DIE(ret < 0, "sprintf() failed\n");
	compute_message(message, line);

	/* Add host, content headers, cookie and token. */
	add_host(message, ip, port, line);
	add_content_type(message, content_type, line);
	add_content_length(message, strlen(content), line);
	add_cookie(message, cookie, line);
	add_token(message, token, line);

	/* Close connection after this message. */
    compute_message(message, "Connection: close");

	/* Add new line at end of header */
	compute_message(message, "");

	/* Add the actual payload data */
	strcat(message, content);

	memset(line, 0, LINELEN);
	free(line);
	return message;
}

char *compute_get_request(char *ip, int port, char *url,
						  char *cookie, char *token)
{
	return compute_basic_request("GET", ip, port, url, cookie, token);
}

char *compute_delete_request(char *ip, int port, char *url,
						  	 char *cookie, char *token)
{
	return compute_basic_request("DELETE", ip, port, url, cookie, token);
}

char *compute_post_request(char *ip, int port, char *url, char* content_type,
						   char *content, char *cookie, char *token)
{
	return compute_content_request("POST", ip, port, url, content_type,
			content, cookie, token);
}

char *compute_put_request(char *ip, int port, char *url, char* content_type,
						   char *content, char *cookie, char *token)
{
	return compute_content_request("PUT", ip, port, url, content_type,
			content, cookie, token);
}

