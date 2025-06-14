#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
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
				sizeof(serv_addr)
	);
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

	do
	{
		int bytes = read(sockfd, response, BUFLEN);

		DIE(bytes < 0, "ERROR reading response from socket");

		if (bytes == 0)
		{
			break;
		}

		buffer_add(&buffer, response, (size_t) bytes);
		
		header_end = buffer_find(&buffer, HEADER_TERMINATOR,
						HEADER_TERMINATOR_SIZE);

		if (header_end >= 0)
		{
			header_end += HEADER_TERMINATOR_SIZE;
			
			int content_length_start = buffer_find_insensitive(&buffer,
						CONTENT_LENGTH, CONTENT_LENGTH_SIZE);
			
			if (content_length_start < 0)
			{
				continue;           
			}

			content_length_start += CONTENT_LENGTH_SIZE;
			content_length = strtol(buffer.data + content_length_start,
						NULL, 10);
			break;
		}
	} while (1);

	size_t total = content_length + (size_t) header_end;
	while (buffer.size < total)
	{
		int bytes = read(sockfd, response, BUFLEN);

		DIE(bytes < 0, "ERROR reading response from socket");

		if (bytes == 0)
		{
			break;
		}

		buffer_add(&buffer, response, (size_t) bytes);
	}

	buffer_add(&buffer, "", 1);
	return buffer.data;
}

char *basic_extract_json_response(const char *const str)
{
	return strstr(str, "{\"");
}

char *extract_from_http_response(const char *const response,
		const char *const field)
{
	char *start_line = strstr(response, field);
	if (!start_line)
	{
		return NULL;
	}

	char *end_line = strstr(start_line, "\r\n");
	if (!start_line)
	{
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

char *get_string_from_json_string(char* json_string, char *field_name)
{
	JSON_Value *root_value;
	JSON_Object *root_object;
	const char *field_value;
	char *field_value_copy;

	root_value = json_parse_string(json_string);
	DIE(root_value == NULL, "json_parse_string() failed\n");

	root_object = json_value_get_object(root_value);
	DIE(root_object == NULL, "json_value_get_object() failed\n");

	field_value = json_object_get_string(root_object, field_name);
	if (!field_value) {
		return NULL;
	}
 
	field_value_copy = (char *) malloc(sizeof(char) * 
		(strlen(field_value) + 1)
	);
	DIE(!field_value_copy, "malloec() failed\n");
	memcpy(field_value_copy, field_value, strlen(field_value) + 1);

	json_value_free(root_value);
	return field_value_copy;
}

double get_number_from_json_string(char* json_string, char *field_name)
{
	JSON_Value *root_value;
	JSON_Object *root_object;
	double field_value;

	root_value = json_parse_string(json_string);
	DIE(root_value == NULL, "json_parse_string() failed\n");

	root_object = json_value_get_object(root_value);
	DIE(root_object == NULL, "json_value_get_object() failed\n");

	field_value = json_object_get_number(root_object, field_name);

	json_value_free(root_value);
	return field_value;
}

void read_line(char *const buff, const int len)
{
	char *ret;

	/* Read. */
	ret = fgets(buff, len, stdin);
	DIE(ret == NULL, "fgets() failed\n");

	/* Remoove new line character. */
	buff[strlen(buff) - 1] = '\0';
}

void get_http_response_code(const char *const response, char *const code)
{
	char *start;

	start = strchr(response, ' ');
	DIE(start == NULL, "Wrong format for the http response.\n");
	start++;

	memcpy(code, start, 3);
	code[4] = '\0';
}

int basic_print_http_response_with_content(char *const response)
{
	char *response_payload, *message;

	/* Do we have something in payload? */
	response_payload = basic_extract_json_response(response);
	if (response_payload == NULL)
	{
		return -1;
	}
	else if (strstr(response_payload, "\"error\":"))
	{
		message = get_string_from_json_string(response_payload, "error");

		printf("ERROR: %s\n", message);
		free(message);
		return 4;
	}
	else if (strstr(response_payload, "\"message\":"))
	{
		message = get_string_from_json_string(response_payload, "message");

		printf("SUCCESS: %s\n", message);
		free(message);
		return 2;
	}

	return -1;
}

int basic_print_http_response(char *const response, const char *const success_msg)
{
	char code[4] = {'\0'};
	
	/* Make a discussion after code. */
	get_http_response_code(response, code);

	if (code[0] == '2')
	{
		printf("SUCCESS: %s\n", success_msg);
		return 2;
	}
	else if (code[0] == '4')
	{
		printf("ERROR: You did something wrong. (code %s)\n", code);
		return 4;
	}
	else if (code[0] == '5')
	{
		printf("ERROR: Server error (code %s)\n",  code);
		return 5;
	}
	return -1;
}

JSON_Value *get_json_val_from_string(const char *const json_string)
{
	JSON_Value *value;

	value = json_parse_string(json_string);
	DIE(value == NULL, "json_parse_string() failed\n");

	return value;
}

JSON_Array *get_json_array_from_json_val(JSON_Value *value,
	const char *const field_name)
{
	JSON_Object *object;
	JSON_Array  *array;

	object = json_value_get_object(value);
	DIE(object == NULL, "json_value_get_object() failed\n");

	array = json_object_get_array(object, field_name);
	DIE(array == NULL, "json_object_get_array() failed\n");

	return array;
}

char *get_pretty_string_from_json_string(const char *string)
{
	JSON_Value *root_value;
	char *pretty_string;

	root_value = json_parse_string(string);
	DIE(root_value == NULL, "json_parse_string() failed\n");

	pretty_string = json_serialize_to_string_pretty(root_value);
	DIE(pretty_string == NULL, "json_serialize_to_string_pretty() failed\n");

	json_value_free(root_value);
	return pretty_string;
}

size_t atos(const char *const string)
{
	size_t number;
	int len, digit;

	if (string == NULL)
	{
		return SIZE_T_MAX;
	}
	
	len = strlen(string);
	if (len == 0 || !('1' <= string[0] && string[0] <= '9'))
	{
		return SIZE_T_MAX;
	}

	number = 0;
	for (int i = 0; i < len; ++i)
	{
		/* Is digit? */
		if (!('0' <= string[0] && string[0] <= '9'))
		{
			return SIZE_T_MAX;
		}

		/* Does it overflow? */
		digit = string[i] - '0';
		if (number * 10 + digit < number)
		{
			return SIZE_T_MAX;
		}

		/* Add the new digit. */
		number = number * 10 + digit;
	}

	return number;
}
