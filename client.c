#include <stdio.h>      /* printf, sprintf, fgets */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include <stdbool.h>
#include "helper.h"
#include "requests.h"
#include "parson.h"
#include "client.h"

// void add_user(const int sockfd)
// {
// 	char username[LINELEN];
// 	char password[LINELEN];
// 	char content[LINELEN];
// 	char *msg, *response;
// 	int ret;

// 	/* Get the username. */
// 	printf("username=");
// 	read_line(username, LINELEN);

// 	/* Get the pasword. */
// 	printf("password=");
// 	read_line(password, LINELEN);

// 	/* Create the payload. */
// 	ret = snprintf(content, LINELEN, ADD_USER_CONTENT_FORMAT,
// 			username, password
// 	);
// 	DIE(ret < 0, "snprintf() failed\n");
	
// 	/* Create the request. */
// 	msg = compute_post_request(SRV_IP, SRV_PORT, ADD_USER_URL,
// 				ADD_USER_CONTENT_TYPE, content, cookie, NULL
// 	);

// 	/* Communicate with the server. */
// 	send_to_server(sockfd, msg);
// 	response = receive_from_server(sockfd);

// 	/* How did the server answer? */
// 	basic_print_http_response(response, NULL);

// 	/* Free the memory. */
// 	free(msg);
// 	free(response);
// }

// void logout_admin(const int sockfd)
// {
// 	char *msg, *response, *resp_payload;
	
// 	/* Create the request. */
// 	msg = compute_get_request(SRV_IP, SRV_PORT, LOGOUT_ADMIN_URL,
// 				cookie, NULL);

// 	/* Communicate with the server. */
// 	send_to_server(sockfd, msg);
// 	response = receive_from_server(sockfd);

// 	/* How did the server answer? */
// 	resp_payload = basic_extract_json_response(response);
// 	if (resp_payload && !strstr(resp_payload, "\"error\"")) {
// 		free(cookie);
// 		//free(token);

// 		cookie = NULL;
// 		//token = NULL;
// 	}
// 	basic_print_http_response(response, NULL);

// 	/* Free the memory. */
// 	free(msg);
// 	free(response);
// }

// void login(const int sockfd)
// {
// 	char admin_username[LINELEN];
// 	char username[LINELEN];
// 	char password[LINELEN];
// 	char content[LINELEN];
// 	char *msg, *response;
// 	int ret;

// 	/* Get the admin username. */
// 	printf("admin_username=");
// 	read_line(admin_username, LINELEN);

// 	/* Get the username. */
// 	printf("username=");
// 	read_line(username, LINELEN);

// 	/* Get the pasword. */
// 	printf("password=");
// 	read_line(password, LINELEN);

// 	/* Create the payload. */
// 	ret = snprintf(content, LINELEN, LOGIN_CONTENT_FORMAT,
// 			admin_username, username, password
// 	);
// 	DIE(ret < 0, "snprintf() failed\n");
	
// 	/* Create the request. */
// 	msg = compute_post_request(SRV_IP, SRV_PORT, LOGIN_URL,
// 				LOGIN_CONTENT_TYPE, content, cookie, NULL
// 	);

// 	/* Communicate with the server. */
// 	send_to_server(sockfd, msg);
// 	response = receive_from_server(sockfd);

// 	/* How did the server answer? */
// 	get_new_cookie(response);
// 	basic_print_http_response(response, NULL);

// 	/* Free the memory. */
// 	free(msg);
// 	free(response);
// }

// void logout(const int sockfd)
// {
// 	char *msg, *response, *resp_payload;
	
// 	/* Create the request. */
// 	msg = compute_get_request(SRV_IP, SRV_PORT, LOGOUT_URL,
// 				cookie, NULL);

// 	/* Communicate with the server. */
// 	send_to_server(sockfd, msg);
// 	response = receive_from_server(sockfd);

// 	/* How did the server answer? */
// 	resp_payload = basic_extract_json_response(response);
// 	if (resp_payload && !strstr(resp_payload, "\"error\"")) {
// 		free(cookie);
// 		//free(token);

// 		cookie = NULL;
// 		//token = NULL;
// 	}
// 	basic_print_http_response(response, NULL);

// 	/* Free the memory. */
// 	free(msg);
// 	free(response);
// }

// void get_access(const int sockfd)
// {
// 	char *msg, *response, *resp_payload;
	
// 	/* Create the request. */
// 	msg = compute_get_request(SRV_IP, SRV_PORT, GET_ACCESS_URL,
// 				cookie, NULL);

// 	/* Communicate with the server. */
// 	send_to_server(sockfd, msg);
// 	response = receive_from_server(sockfd);

// 	/* How did the server answer? */
// 	resp_payload = basic_extract_json_response(response);
// 	if (resp_payload && strstr(resp_payload, "\"token\"")) {
// 		token = extract_from_json_response(resp_payload, "\"token\"");
// 		printf("SUCCESS: Received the JWT token.\n");
// 	} else {
// 		basic_print_http_response(response, NULL);
// 	}

// 	/* Free the memory. */
// 	free(msg);
// 	free(response);
// }

// void get_users(const int sockfd)
// {
// 	char *msg, *response, *resp_payload, *pretty_payload;
// 	JSON_Value *root_val;
// 	JSON_Array *users;
// 	JSON_Object *root_obj, *user_obj;
	
// 	/* Create the request. */
// 	msg = compute_get_request(SRV_IP, SRV_PORT, GET_USERS_URL,
// 				cookie, NULL);

// 	/* Communicate with the server. */
// 	send_to_server(sockfd, msg);
// 	response = receive_from_server(sockfd);

// 	/* How did the server answer? */
// 	resp_payload = basic_extract_json_response(response);
// 	if (resp_payload && !strstr(resp_payload, "\"error\"")) {
// 		root_val = json_parse_string(resp_payload);
// 		DIE(root_val == NULL, "json_parse_string() failed\n");

// 		root_obj = json_value_get_object(root_val);
// 		DIE(root_obj == NULL, "json_value_get_object() failed\n");

// 		printf("SUCCESS: Users list \n");

//     	users = json_object_get_array(root_obj, "movies");

// 	    int size = json_array_get_count(users);
//     	for (int i = 0; i < size; i++) {
//         	user_obj = json_array_get_object(users, i);

//             printf("#%d %s\n", i + 1, json_object_get_string(user_obj, "title"));
//         }

// 		json_value_free(root_val);
// 	} else {
// 		basic_print_http_response(response, NULL);
// 	}

// 	/* Free the memory. */
// 	free(msg);
// 	free(response);
// }

// void delete_user(const int sockfd)
// {
// 	char *msg, *response;
// 	char username[LINELEN];
// 	char url[2 * LINELEN];
// 	int ret;
	
// 	/* Get the username. */
// 	printf("username=");
// 	read_line(username, LINELEN);

// 	/* Complete the url. */
// 	ret = snprintf(url, sizeof(url), DELETE_USER_URL, username);
// 	DIE(ret < 0, "snprintf() failed\n");

// 	/* Create the request. */
// 	msg = compute_delete_request(SRV_IP, SRV_PORT, url, cookie, NULL);

// 	/* Communicate with the server. */
// 	send_to_server(sockfd, msg);
// 	response = receive_from_server(sockfd);

// 	/* How did the server answer? */
// 	basic_print_http_response(response, NULL);

// 	/* Free the memory. */
// 	free(msg);
// 	free(response);
// }

// void get_movies(const int sockfd)
// {
// 	char *msg, *response, *resp_payload, *pretty_payload;
// 	const char *id, *title;
// 	JSON_Value *root_val;
// 	JSON_Array *movies;
// 	JSON_Object *root_obj, *movie_obj;

	
// 	/* Create the request. */
// 	msg = compute_get_request(SRV_IP, SRV_PORT, GET_MOVIES_URL,
// 				NULL, token);

// 	/* Communicate with the server. */
// 	send_to_server(sockfd, msg);
// 	response = receive_from_server(sockfd);

// 	/* How did the server answer? */
// 	resp_payload = basic_extract_json_response(response);
// 	if (resp_payload && !strstr(resp_payload, "\"error\"")) {
// 		root_val = json_parse_string(resp_payload);
// 		DIE(root_val == NULL, "json_parse_string() failed\n");

// 		root_obj = json_value_get_object(root_val);
// 		DIE(root_obj == NULL, "json_value_get_object() failed\n");

// 		printf("SUCCESS: Movies list \n");

//     	movies = json_object_get_array(root_obj, "movies");

// 	    int size = json_array_get_count(movies);
//     	for (int i = 0; i < size; i++) {
//         	movie_obj = json_array_get_object(movies, i);
// 			id = json_object_get_string(movie_obj, "id");
// 			title = json_object_get_string(movie_obj, "title");

// 			printf("#%d %s\n", i + 1, title);
//         }

// 		json_value_free(root_val);
// 	} else {
// 		basic_print_http_response(response, NULL);
// 	}

// 	/* Free the memory. */
// 	free(msg);
// 	free(response);
// }

// void get_movie(const int sockfd)
// {
// 	char *msg, *response, *resp_payload, *pretty_payload;
// 	char id[LINELEN];
// 	char url[2 * LINELEN];
// 	int ret;
// 	JSON_Value *root_val;
	
// 	/* Get the username. */
// 	printf("id=");
// 	read_line(id, LINELEN);

// 	/* Complete the url. */
// 	ret = snprintf(url, sizeof(url), GET_MOVIE_URL, id);
// 	DIE(ret < 0, "snprintf() failed\n");

// 	/* Create the request. */
// 	msg = compute_get_request(SRV_IP, SRV_PORT, url,
// 				NULL, token);

// 	/* Communicate with the server. */
// 	send_to_server(sockfd, msg);
// 	response = receive_from_server(sockfd);

// 	/* How did the server answer? */
// 	resp_payload = basic_extract_json_response(response);
// 	if (resp_payload && !strstr(resp_payload, "\"error\"")) {
// 		root_val = json_parse_string(resp_payload);
// 		DIE(root_val == NULL, "json_parse_string() failed\n");

// 		pretty_payload = json_serialize_to_string_pretty(root_val);
// 		DIE(pretty_payload == NULL, "json_serialize_to_string_pretty() failed\n");

// 		printf("SUCCESS:\n%s\n", pretty_payload);

// 		free(pretty_payload);
// 		json_value_free(root_val);
//     } else {
// 		basic_print_http_response(response, NULL);
// 	}

// 	/* Free the memory. */
// 	free(msg);
// 	free(response);
// }

// void add_movie(const int sockfd)
// {
// 	char *msg, *response;
// 	char title[LINELEN];
// 	char year[LINELEN];
// 	char description[LINELEN];
// 	char rating[LINELEN];
// 	char content[LINELEN];
// 	int ret;

// 	/* Get the title. */
// 	printf("title=");
// 	read_line(title, LINELEN);

// 	/* Get the year. */
// 	printf("year=");
// 	read_line(year, LINELEN);

// 	/* Get the description. */
// 	printf("description=");
// 	read_line(description, LINELEN);

// 	/* Get the rating. */
// 	printf("rating=");
// 	read_line(rating, LINELEN);

// 	/* Create the payload. */
// 	ret = snprintf(content, LINELEN, ADD_MOVIE_CONTENT_FORMAT,
// 			title, year, description, rating
// 	);
// 	DIE(ret < 0, "snprintf() failed\n");
	
// 	/* Create the request. */
// 	msg = compute_post_request(SRV_IP, SRV_PORT, ADD_MOVIE_URL,
// 				ADD_MOVIE_CONTENT_TYPE, content, cookie, token
// 	);

// 	/* Communicate with the server. */
// 	send_to_server(sockfd, msg);
// 	response = receive_from_server(sockfd);

// 	/* How did the server answer? */
// 	basic_print_http_response(response, "Movie added successfully.");

// 	/* Free the memory. */
// 	free(msg);
// 	free(response);
// }

void init_client(client_t *client)
{
	client->sock_fd = -1;
	client->cookie = NULL;
	client->token = NULL;
}

void get_new_cookie(client_t *const client, const char *const response) {
	if (strstr(response, "\r\nSet-Cookie:")) {
		client->cookie = extract_from_http_response(response, "Set-Cookie");
	}
}

char *get_login_admin_request() {
	char username[LINELEN];
	char password[LINELEN];
	char payload[LINELEN];
	char *request;
	int ret;

	/* Get the username. */
	printf("username=");
	read_line(username, LINELEN);

	/* Get the pasword. */
	printf("password=");
	read_line(password, LINELEN);

	/* Create the payload. */
	ret = snprintf(payload, sizeof(payload), LOGIN_ADMIN_CONTENT_FORMAT,
			username, password
	);
	DIE(ret < 0, "snprintf() failed\n");
	
	/* Create the request. */
	request = compute_post_request(SRV_IP, SRV_PORT, LOGIN_ADMIN_URL,
				LOGIN_ADMIN_CONTENT_TYPE, payload, NULL, NULL
	);

	return request;
}

void login_admin(client_t *const client)
{
	char *request, *response;
	
	/* Create the request. */
	request = get_login_admin_request();

	/* Communicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	get_new_cookie(client, response);
	if (basic_print_http_response_with_content(response) == -1) {
		print_http_response(response, "Admin logged in successfully.");
	}

	/* Free the memory. */
	free(request);
	free(response);
}

void stop_program(client_t *const client) {
	int ret;

	if (client->cookie)
	{
		free(client->cookie);
	}
	if (client->token)
	{
		free(client->token);
	}
	if (client->sock_fd > 0)
	{
		ret = close(client->sock_fd);
		DIE(ret == -1, "close() failed\n");
	}

	exit(0);
}

bool handle_user_command(client_t *const client, const char *command)
{
	if (!strcmp(command, LOGIN_ADMIN_CMD))
	{
		login_admin(client);
		return true;
	}
	else if (!strcmp(command, LOGIN_CMD))
	{
		//login(sockfd);
		return true;
	}
	else if (!strcmp(command, ADD_USER_CMD))
	{
		//add_user(sockfd);
		return true;
	}
	else if (!strcmp(command, DELETE_USER_CMD))
	{
		//delete_user(sockfd);
		return true;
	}
	else if (!strcmp(command, GET_USERS_CMD))
	{
		//get_users(sockfd);
		return true;
	}
	else if (!strcmp(command, GET_ACCESS_CMD))
	{
		//get_access(sockfd);
		return true;
	}
	else if (!strcmp(command, LOGOUT_ADMIN_CMD))
	{
		//logout_admin(sockfd);
		return true;
	}
	else if (!strcmp(command, LOGOUT_CMD))
	{
		//logout(sockfd);
		return true;
	}

	return false;
}

bool handle_movie_command(client_t *const client, const char *command)
{
	if (!strcmp(command, ADD_MOVIE_CMD))
	{
		//add_movie(sockfd);
		return true;
	}
	else if (!strcmp(command, DELETE_MOVIE_CMD))
	{
		//
		return true;
	}
	else if (!strcmp(command, GET_MOVIE_CMD))
	{
		//get_movie(sockfd);
		return true;
	}
	else if (!strcmp(command, GET_MOVIES_CMD))
	{
		//get_movies(sockfd);
		return true;
	}

	return false;
}

bool handle_coll_command(client_t *const client, const char *const command)
{
	if (!strcmp(command, ADD_COLLECTION_CMD))
	{
		//
		return true;
	}
	else if (!strcmp(command, DELETE_COLLECTION_CMD))
	{
		//
		return true;
	}
	else if (!strcmp(command, ADD_MOVIE_TO_COLLECTION_CMD))
	{
		//
		return true;
	}
	else if (!strcmp(command, DELETE_MOVIE_FROM_COLLECTION_CMD))
	{
		//
		return true;
	}
	else if (!strcmp(command, GET_COLLECTION_CMD))
	{
		//
		return true;
	}
	else if (!strcmp(command, GET_COLLECTIONS_CMD))
	{
		//
		return true;
	}

	return false;
}

void handle_command(client_t *const client) {
	char command[LINELEN];
	int ret;
	
	/* Read command. */
	read_line(command, LINELEN);

	/* Open connection. */
	client->sock_fd = open_connection(SRV_IP, SRV_PORT, AF_INET,
			SOCK_STREAM, 0);

	/* Execute the command. */
	if (handle_user_command(client, command))
	{
		goto handled_command;
	}
	else if (handle_movie_command(client, command))
	{
		goto handled_command;
	}
	else if (handle_coll_command(client, command))
	{
		goto handled_command;
	}
	else if (!strcmp(command, EXIT_CMD))
	{
		stop_program(client);
	}
	else
	{
		printf("Invalid command.\n");
	}

handled_command:
	ret = close(client->sock_fd); /* What was remains in past */
	DIE(ret == -1, "close() failed\n");
	client->sock_fd = -1;
}

int main()
{
	client_t client;
	init_client(&client);

	while (1) {
		handle_command(&client);
	}

	return 0;
}
