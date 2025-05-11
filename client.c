#include <stdio.h>      /* printf, sprintf, fgets */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "helper.h"
#include "requests.h"
#include "parson.h"		/* json_parse_string, json_serialize_to_string_pretty
						 * json_free_value */

#define HTTP_VRS "HTTP/1.1"
#define SRV_IP "63.32.125.183"
#define SRV_PORT 8081

#define LOGIN_ADMIN_CMD "login_admin"
#define LOGIN_ADMIN_URL "/api/v1/tema/admin/login"
#define LOGIN_ADMIN_CONTENT_TYPE "application/json"
#define LOGIN_ADMIN_CONTENT_FORMAT											\
	"{"																		\
		"\"username\":\"%s\","												\
		"\"password\":\"%s\""												\
	"}"

#define ADD_USER_CMD "add_user"
#define ADD_USER_URL "/api/v1/tema/admin/users"
#define ADD_USER_CONTENT_TYPE "application/json"
#define ADD_USER_CONTENT_FORMAT												\
	"{"																		\
		"\"username\":\"%s\","												\
		"\"password\":\"%s\""												\
	"}"

#define GET_USERS_CMD "get_users"
#define GET_USERS_URL "/api/v1/tema/admin/users"

#define DELETE_USER_CMD "delete_user"
#define DELETE_USER_URL "/api/v1/tema/admin/users/%s"

#define LOGIN_CMD "login"
#define LOGIN_URL "/api/v1/tema/user/login"
#define LOGIN_CONTENT_TYPE "application/json"
#define LOGIN_CONTENT_FORMAT												\
	"{"																		\
		"\"admin_username\":\"%s\","										\
		"\"username\":\"%s\","												\
		"\"password\":\"%s\""												\
	"}"

#define GET_ACCESS_CMD "get_access"
#define GET_ACCESS_URL "/api/v1/tema/library/access"

#define GET_MOVIES_CMD "get_movies"
#define GET_MOVIES_URL "/api/v1/tema/library/movies"

#define GET_MOVIE_CMD "get_movie"
#define GET_MOVIE_URL "/api/v1/tema/library/movies/%s"

#define ADD_MOVIE_CMD "add_movie"
#define ADD_MOVIE_URL "/api/v1/tema/library/movies"
#define ADD_MOVIE_CONTENT_TYPE "application/json"
#define ADD_MOVIE_CONTENT													\
	"{"																		\
		"\"title\":\"%s\","													\
		"\"year\":\"%d\","													\
		"\"description\":\"%s\""											\
		"\"rating\":\"%f\""													\
	"}"

#define DELETE_MOVIE_CMD "delete_movie"
#define DELETE_MOVIE_URL "/api/v1/tema/library/movies/%s"

#define UPDATE_MOVIE_CMD "update_movie"
#define UPDATE_MOVIE_URL "/api/v1/tema/library/movies/%s"
#define UPDATE_MOVIE_CONTENT_TYPE "application/json"
#define UPDATE_MOVIE_CONTENT												\
	"{"																		\
		"\"title\":\"%s\","													\
		"\"year\":\"%d\","													\
		"\"description\":\"%s\""											\
		"\"rating\":\"%f\""													\
	"}"

#define GET_COLLECTIONS_CMD "get_collections"
#define GET_COLLECTIONS_URL "/api/v1/tema/library/collections"

#define GET_COLLECTION_CMD "get_collection"
#define GET_COLLECTION_URL "/api/v1/tema/library/collections/%s"

#define ADD_COLLECTION_CMD "add_collection"
#define ADD_COLLECTION_URL "/api/v1/tema/library/collections"
#define ADD_COLLECTION_TYPE "application/json"
#define ADD_COLLECTION_CONTENT												\
	"{"																		\
		"\"title\":\"%s\","													\
	"}"

#define DELETE_COLLECTION_CMD "delete_collection"
#define DELETE_COLLECTION_URL "/api/v1/tema/library/collections/%s"

#define ADD_MOVIE_TO_COLLECTION_CMD "add_movie_to_collection"
#define ADD_MOVIE_TO_COLLECTION_URL											\
	"/api/v1/tema/library/collections/%s/movies"
#define ADD_MOVIE_TO_COLLECTION_TYPE "application/json"
#define ADD_MOVIE_TO_COLLECTION_CONTENT										\
	"{"																		\
		"\"id\":\"%d\","													\
	"}"

#define DELETE_MOVIE_FROM_COLLECTION_CMD "delete_movie_from_collection"
#define DELETE_MOVIE_FROM_COLLECTION_URL									\
	"/api/v1/tema/library/collections/%s/movies/%d"

#define LOGOUT_ADMIN_CMD "logout_admin"
#define LOGOUT_ADMIN_URL "/api/v1/tema/admin/logout"

#define LOGOUT_CMD "logout"
#define LOGOUT_URL "/api/v1/tema/user/logout"

#define EXIT_CMD "exit"

char *admin_cookie;
char *user_cookie;
char *token;

void get_new_cookie(char *http_response, char **cookie) {
	if (strstr(http_response, "\r\nSet-Cookie:")) {
		*cookie = extract_from_http_response(http_response, "Set-Cookie");
	}
}

void login_admin(const int sockfd)
{
	char username[LINELEN];
	char password[LINELEN];
	char content[LINELEN];
	char *msg, *response;
	int ret;

	/* Get the username. */
	printf("username=");
	read_line(username, LINELEN);

	/* Get the pasword. */
	printf("password=");
	read_line(password, LINELEN);

	/* Create the payload. */
	ret = snprintf(content, LINELEN, LOGIN_ADMIN_CONTENT_FORMAT,
			username, password
	);
	DIE(ret < 0, "snprintf() failed\n");
	
	/* Create the request. */
	msg = compute_post_request(SRV_IP, SRV_PORT, LOGIN_ADMIN_URL,
				LOGIN_ADMIN_CONTENT_TYPE, content, NULL, NULL
	);

	/* Communicate with the server. */
	send_to_server(sockfd, msg);
	response = receive_from_server(sockfd);

	/* How did the server answer? */
	get_new_cookie(response, &admin_cookie);
	basic_print_http_response(response);

	/* Free the memory. */
	free(msg);
	free(response);
}

void add_user(const int sockfd)
{
	char username[LINELEN];
	char password[LINELEN];
	char content[LINELEN];
	char *msg, *response;
	int ret;

	/* Get the username. */
	printf("username=");
	read_line(username, LINELEN);

	/* Get the pasword. */
	printf("password=");
	read_line(password, LINELEN);

	/* Create the payload. */
	ret = snprintf(content, LINELEN, ADD_USER_CONTENT_FORMAT,
			username, password
	);
	DIE(ret < 0, "snprintf() failed\n");
	
	/* Create the request. */
	msg = compute_post_request(SRV_IP, SRV_PORT, ADD_USER_URL,
				ADD_USER_CONTENT_TYPE, content, admin_cookie, NULL
	);

	/* Communicate with the server. */
	send_to_server(sockfd, msg);
	response = receive_from_server(sockfd);

	/* How did the server answer? */
	basic_print_http_response(response);

	/* Free the memory. */
	free(msg);
	free(response);
}

void logout_admin(const int sockfd)
{
	char *msg, *response, *resp_payload;
	
	/* Create the request. */
	msg = compute_get_request(SRV_IP, SRV_PORT, LOGOUT_ADMIN_URL,
				admin_cookie, NULL);

	/* Communicate with the server. */
	send_to_server(sockfd, msg);
	response = receive_from_server(sockfd);

	/* How did the server answer? */
	resp_payload = basic_extract_json_response(response);
	if (resp_payload && !strstr(resp_payload, "\"error\"")) {
		free(admin_cookie);
		admin_cookie = NULL;
	}
	basic_print_http_response(response);

	/* Free the memory. */
	free(msg);
	free(response);
}

void login(const int sockfd)
{
	char admin_username[LINELEN];
	char username[LINELEN];
	char password[LINELEN];
	char content[LINELEN];
	char *msg, *response;
	int ret;

	/* Get the admin username. */
	printf("admin_username=");
	read_line(admin_username, LINELEN);

	/* Get the username. */
	printf("username=");
	read_line(username, LINELEN);

	/* Get the pasword. */
	printf("password=");
	read_line(password, LINELEN);

	/* Create the payload. */
	ret = snprintf(content, LINELEN, LOGIN_CONTENT_FORMAT,
			admin_username, username, password
	);
	DIE(ret < 0, "snprintf() failed\n");
	
	/* Create the request. */
	msg = compute_post_request_1(SRV_IP, SRV_PORT, LOGIN_URL,
				LOGIN_CONTENT_TYPE, content, admin_cookie, user_cookie, NULL
	);

	/* Communicate with the server. */
	send_to_server(sockfd, msg);
	response = receive_from_server(sockfd);

	/* How did the server answer? */
	get_new_cookie(response, &user_cookie);
	basic_print_http_response(response);

	/* Free the memory. */
	free(msg);
	free(response);
}

void logout(const int sockfd)
{
	char *msg, *response, *resp_payload;
	
	/* Create the request. */
	msg = compute_get_request(SRV_IP, SRV_PORT, LOGOUT_URL,
				admin_cookie, NULL);

	/* Communicate with the server. */
	send_to_server(sockfd, msg);
	response = receive_from_server(sockfd);

	/* How did the server answer? */
	resp_payload = basic_extract_json_response(response);
	if (resp_payload && !strstr(resp_payload, "\"error\"")) {
		free(user_cookie);
		user_cookie = NULL;
	}
	basic_print_http_response(response);

	/* Free the memory. */
	free(msg);
	free(response);
}

void get_access(const int sockfd)
{
	char *msg, *response, *resp_payload;
	
	/* Create the request. */
	msg = compute_get_request(SRV_IP, SRV_PORT, GET_ACCESS_URL,
				user_cookie, NULL);

	/* Communicate with the server. */
	send_to_server(sockfd, msg);
	response = receive_from_server(sockfd);

	/* How did the server answer? */
	resp_payload = basic_extract_json_response(response);
	if (resp_payload && strstr(resp_payload, "\"token\"")) {
		token = extract_from_json_response(resp_payload, "\"token\"");
		printf("SUCCESS: Received the JWT token.\n");
	} else {
		basic_print_http_response(response);
	}

	/* Free the memory. */
	free(msg);
	free(response);
}

void get_users(const int sockfd)
{
	char *msg, *response, *resp_payload, *pretty_payload;
	JSON_Value *root; 

	
	/* Create the request. */
	msg = compute_get_request(SRV_IP, SRV_PORT, GET_USERS_URL,
				admin_cookie, NULL);

	/* Communicate with the server. */
	send_to_server(sockfd, msg);
	response = receive_from_server(sockfd);

	/* How did the server answer? */
	resp_payload = basic_extract_json_response(response);
	if (resp_payload && !strstr(resp_payload, "\"error\"")) {
		root = json_parse_string(resp_payload);
		DIE(root == NULL, "json_parse_string() failed\n");

		pretty_payload = json_serialize_to_string_pretty(root);
		DIE(pretty_payload == NULL, "json_serialize_to_string_pretty() failed\n");

		printf("SUCCESS:\n%s\n", pretty_payload);
	} else {
		basic_print_http_response(response);
	}

	/* Free the memory. */
	free(msg);
	free(response);
	free(pretty_payload);
	json_value_free(root);
}

void delete_user(const int sockfd)
{
	char *msg, *response;
	char username[LINELEN];
	char url[2 * LINELEN];
	int ret;
	
	/* Get the username. */
	printf("username=");
	read_line(username, LINELEN);

	/* Complete the url. */
	ret = snprintf(url, sizeof(url), DELETE_USER_URL, username);
	DIE(ret < 0, "snprintf() failed\n");

	/* Create the request. */
	msg = compute_get_request(SRV_IP, SRV_PORT, url, admin_cookie, NULL);

	/* Communicate with the server. */
	send_to_server(sockfd, msg);
	response = receive_from_server(sockfd);

	/* How did the server answer? */
	basic_print_http_response(response);

	/* Free the memory. */
	free(msg);
	free(response);
}

int main()
{
	char command[LINELEN];
	char *string;
	int sockfd, ret;

	admin_cookie = NULL;
	user_cookie = NULL;
	token = NULL;
	while (1) {
		/* Read command. */
		string = fgets(command, LINELEN, stdin);
		DIE(string == NULL, "fgets() failed\n");
		command[strlen(command) - 1] = '\0';

		/* Open connection. */
		sockfd = open_connection(SRV_IP, SRV_PORT, AF_INET, SOCK_STREAM, 0);

		/* Execute the command. */
		if (!strcmp(command, LOGIN_ADMIN_CMD)) {
			login_admin(sockfd);
		} else if (!strcmp(command, ADD_USER_CMD)) {
			add_user(sockfd);
		} else if (!strcmp(command, GET_USERS_CMD)) {
			get_users(sockfd);
		} else if (!strcmp(command, DELETE_USER_CMD)) {
			delete_user(sockfd);
		} else if (!strcmp(command, LOGIN_CMD)) {
			login(sockfd);
		} else if (!strcmp(command, GET_ACCESS_CMD)) {
			get_access(sockfd);
		} else if (!strcmp(command, GET_MOVIES_CMD)) {
			//
		} else if (!strcmp(command, GET_MOVIE_CMD)) {
			//
		} else if (!strcmp(command, ADD_MOVIE_CMD)) {
			//
		} else if (!strcmp(command, DELETE_MOVIE_CMD)) {
			//
		} else if (!strcmp(command, GET_COLLECTIONS_CMD)) {
			//
		} else if (!strcmp(command, GET_COLLECTION_CMD)) {
			//
		} else if (!strcmp(command, ADD_COLLECTION_CMD)) {
			//
		} else if (!strcmp(command, DELETE_COLLECTION_CMD)) {
			//
		} else if (!strcmp(command, ADD_MOVIE_TO_COLLECTION_CMD)) {
			//
		} else if (!strcmp(command, DELETE_MOVIE_FROM_COLLECTION_CMD)) {
			//
		} else if (!strcmp(command, LOGOUT_ADMIN_CMD)) {
			logout_admin(sockfd);
		} else if (!strcmp(command, LOGOUT_CMD)) {
			logout(sockfd);
		} else if (!strcmp(command, EXIT_CMD)) {
			break;
		} else {
			printf("Invalid command.\n");
		}

		ret = close(sockfd);
		DIE(ret == -1, "close() failed\n");
	}

	/* Free the memory */
	if (admin_cookie != NULL) {
		free(admin_cookie);
	}
	if (user_cookie != NULL) {
		free(user_cookie);
	}
	if (token != NULL) {
		free(token);
	}

	/* Close the connection. */
	close(sockfd);
	DIE(ret == -1, "close() failed\n");

	return 0;
}
