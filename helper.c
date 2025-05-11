#include <stdlib.h>     /* exit, atoi, malloc, free , strpbrk, strlen*/
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helper.h"
#include "buffer.h"

void compute_message(char *message, const char *line)
{
    strcat(message, line);
    strcat(message, "\r\n");
}

int open_connection(char *host_ip, int portno, int ip_type,
                    int socket_type, int flag)
{
    struct sockaddr_in serv_addr;
    int sockfd = socket(ip_type, socket_type, flag);
    DIE(sockfd < 0, "ERROR opening socket");

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = ip_type;
    serv_addr.sin_port = htons(portno);
    inet_aton(host_ip, &serv_addr.sin_addr);

    /* connect the socket */
    int ret = connect(sockfd, (struct sockaddr*) &serv_addr,
                sizeof(serv_addr));
    DIE(ret < 0, "ERROR connecting");

    return sockfd;
}

void close_connection(int sockfd)
{
    close(sockfd);
}

void send_to_server(int sockfd, char *message)
{
    int bytes, sent = 0;
    int total = strlen(message);

    do
    {
        bytes = write(sockfd, message + sent, total - sent);

        DIE(bytes < 0, "ERROR writing message to socket");

        if (bytes == 0) {
            break;
        }

        sent += bytes;
    } while (sent < total);
}

char *receive_from_server(int sockfd)
{
    char response[BUFLEN];
    buffer buffer = buffer_init();
    int header_end = 0;
    int content_length = 0;

    do {
        int bytes = read(sockfd, response, BUFLEN);

        DIE(bytes < 0, "ERROR reading response from socket");

        if (bytes == 0) {
            break;
        }

        buffer_add(&buffer, response, (size_t) bytes);
        
        header_end = buffer_find(&buffer, HEADER_TERMINATOR,
                        HEADER_TERMINATOR_SIZE);

        if (header_end >= 0) {
            header_end += HEADER_TERMINATOR_SIZE;
            
            int content_length_start = buffer_find_insensitive(&buffer,
                        CONTENT_LENGTH, CONTENT_LENGTH_SIZE);
            
            if (content_length_start < 0) {
                continue;           
            }

            content_length_start += CONTENT_LENGTH_SIZE;
            content_length = strtol(buffer.data + content_length_start,
                        NULL, 10);
            break;
        }
    } while (1);

    size_t total = content_length + (size_t) header_end;
    while (buffer.size < total) {
        int bytes = read(sockfd, response, BUFLEN);

        DIE(bytes < 0, "ERROR reading response from socket");

        if (bytes == 0) {
            break;
        }

        buffer_add(&buffer, response, (size_t) bytes);
    }

    buffer_add(&buffer, "", 1);
    return buffer.data;
}

char *basic_extract_json_response(char *str)
{
    return strstr(str, "{\"");
}

char *extract_from_http_response(char* response, char *field)
{
    char *start_line = strstr(response, field);
    if (!start_line) {
        return NULL;
    }

    char *end_line = strstr(start_line, "\r\n");
    if (!start_line) {
        return NULL;
    }

    /* Allocate memory. */
    int offset = strlen(field) + 2;  /* +2 for ": " */
    int len = end_line - start_line - offset + 1; /* +1 for the null char */
    char *value = malloc(len);
    DIE(!value, "malloc() failed\n");

    /* Coppy the value. */
    memcpy(value, start_line + offset, len - 1);
    value[len - 1] = '\0';

    return value;
}

char *extract_from_json_response(char* response, char *field)
{
    char *start_line = strstr(response, field);
    if (!start_line) {
        return NULL;
    }

    int offset = strlen(field) +
        (start_line[strlen(field) + 1] == '\"' ? 2 : 1);  /* +2 for ":\"" */

    char *end_line = strpbrk(start_line + offset, "\",}");
    if (!start_line) {
        return NULL;
    }

    /* Allocate memory. */
    int len = end_line - start_line - offset + 1; /* +1 for the null char */
    char *value = malloc(len);
    DIE(!value, "malloc() failed\n");

    /* Coppy the value. */
    memcpy(value, start_line + offset, len - 1);
    value[len - 1] = '\0';

    return value;
}

void read_line(char *buff, int len)
{
    char *ret;

    /* Read. */
    ret = fgets(buff, len, stdin);
	DIE(ret == NULL, "fgets() failed\n");

    /* Remoove new line character. */
	buff[strlen(buff) - 1] = '\0';
}

void basic_print_http_response(char *response)
{
    char *resp_payload, *json_value, *ret;

    resp_payload = basic_extract_json_response(response);
    if (!resp_payload) {
        ret = strtok(response, "\n");
        DIE(ret == NULL, "strtok() failed\n");
		printf("ERROR: %s\n", response);
    } else if (strstr(resp_payload, "\"error\"")) {	/* Error */
		json_value = extract_from_json_response(resp_payload, "\"error\"");
		printf("ERROR: %s\n", json_value);
        free(json_value);
	} else {	/* Success */
		json_value = extract_from_json_response(resp_payload, "\"message\"");
		printf("SUCCESS: %s\n", json_value);
        free(json_value);
	}
}
