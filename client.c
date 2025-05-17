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

void init_client(client_t *client)
{
	client->sock_fd = -1;
	client->cookie = NULL;
	client->token = NULL;
}

void get_new_token(client_t *const client, const char *const response)
{
	char *response_payload, *token;

	response_payload = basic_extract_json_response(response);
	token = get_string_from_json_string(response_payload, "token");
	if (token)
	{
		if (client->token) {
			free(client->token);
		}
		client->token = token;
	}
}

void get_new_cookie(client_t *const client, const char *const response)
{	
	if (strstr(response, "\r\nSet-Cookie:")) {
		if (client->cookie) {
			free(client->cookie);
		}
		client->cookie = extract_from_http_response(response, "Set-Cookie");
	}
}

void delete_client_info(client_t *const client, const char *const response) 
{
	char *resp_payload;

	resp_payload = basic_extract_json_response(response);
	if (resp_payload && !strstr(resp_payload, "\"error\":"))
	{
		free(client->cookie);
		client->cookie = NULL;

		free(client->token);
		client->token = NULL;
	}
}

char *get_login_admin_request(const client_t *const client)
{
	char username[LINELEN];
	char password[LINELEN];
	char payload[3 * LINELEN];
	int ret;

	/* Get the username. */
	printf("username=");
	read_line(username, sizeof(username));

	/* Get the pasword. */
	printf("password=");
	read_line(password, sizeof(password));

	/* Create the payload. */
	ret = snprintf(payload, sizeof(payload), LOGIN_ADMIN_CONTENT_FORMAT,
			username, password
	);
	DIE(ret < 0, "snprintf() failed\n");
	
	/* Create the request. */
	return compute_post_request(SRV_IP, SRV_PORT, LOGIN_ADMIN_URL,
			LOGIN_ADMIN_CONTENT_TYPE, payload, client->cookie, client->token
	);
}

void login_admin(client_t *const client)
{
	char *request, *response;
	
	/* Create the request. */
	request = get_login_admin_request(client);

	/* Communicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	get_new_cookie(client, response);
	if (basic_print_http_response_with_content(response) == -1)
	{
		basic_print_http_response(response, "Admin logged in successfully.");
	}

	/* Free the memory. */
	free(request);
	free(response);
}

void logout_admin(client_t *const client)
{
	char *request, *response;

	/* Create the request. */
	request = compute_get_request(SRV_IP, SRV_PORT, LOGOUT_ADMIN_URL,
				client->cookie, NULL);

	/* Communicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	delete_client_info(client, response);
	if (basic_print_http_response_with_content(response) == -1)
	{
		basic_print_http_response(response, "Admin logged out successfully.");
	}

	/* Free the memory. */
	free(request);
	free(response);
}

char *get_login_request(const client_t *const client)
{
	char admin_username[LINELEN];
	char username[LINELEN];
	char password[LINELEN];
	char payload[4 * LINELEN];
	int ret;

	/* Get the admin username. */
	printf("admin_username=");
	read_line(admin_username, sizeof(admin_username));

	/* Get the username. */
	printf("username=");
	read_line(username, sizeof(username));

	/* Get the pasword. */
	printf("password=");
	read_line(password, sizeof(password));

	/* Create the payload. */
	ret = snprintf(payload, sizeof(payload), LOGIN_CONTENT_FORMAT,
			admin_username, username, password
	);
	DIE(ret < 0, "snprintf() failed\n");
	
	/* Create the request. */
	return compute_post_request(SRV_IP, SRV_PORT, LOGIN_URL,
			LOGIN_CONTENT_TYPE, payload, client->cookie, client->token
	);
}

void login(client_t *const client)
{
	char *request, *response;
	
	/* Create the request. */
	request = get_login_request(client);

	/* Communicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	get_new_cookie(client,response);
	if (basic_print_http_response_with_content(response) == -1)
	{
		basic_print_http_response(response, "User logged in successfully.");
	}

	/* Free the memory. */
	free(request);
	free(response);
}

void logout(client_t *const client)
{
	char *request, *response;
	
	/* Create the request. */
	request = compute_get_request(SRV_IP, SRV_PORT, LOGOUT_URL,
			client->cookie, client->token
	);

	/* Communicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	delete_client_info(client, response);
	if (basic_print_http_response_with_content(response) == -1)
	{
		basic_print_http_response(response, "User logged out successfully.");
	}

	/* Free the memory. */
	free(request);
	free(response);
}

char *get_add_user_request(const client_t *const client)
{
	char username[LINELEN];
	char password[LINELEN];
	char payload[3 * LINELEN];
	int ret;

	/* Get the username. */
	printf("username=");
	read_line(username, sizeof(username));

	/* Get the pasword. */
	printf("password=");
	read_line(password, sizeof(password));

	/* Create the payload. */
	ret = snprintf(payload, sizeof(payload), ADD_USER_CONTENT_FORMAT,
			username, password
	);
	DIE(ret < 0, "snprintf() failed\n");
	
	/* Create the request. */
	return compute_post_request(SRV_IP, SRV_PORT, ADD_USER_URL,
			ADD_USER_CONTENT_TYPE, payload, client->cookie, client->token
	);
}

void add_user(const client_t *const client)
{
	char *request, *response;

	/* Create the request. */
	request = get_add_user_request(client);

	/* Communicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	if (basic_print_http_response_with_content(response) == -1)
	{
		basic_print_http_response(response,
			"The usser was added successfully.");
	}

	/* Free the memory. */
	free(request);
	free(response);
}

char *get_delete_user_request(const client_t *const client)
{
	char username[LINELEN];
	char url[2 * LINELEN];
	int ret;

	/* Get the username. */
	printf("username=");
	read_line(username, sizeof(username));

	/* Complete the url. */
	ret = snprintf(url, sizeof(url), DELETE_USER_URL, username);
	DIE(ret < 0, "snprintf() failed\n");

	/* Create the request. */
	return compute_delete_request(SRV_IP, SRV_PORT, url,
			client->cookie, client->token);

}

void delete_user(const client_t *const client)
{
	char *request, *response;

	/* Create the request. */
	request = get_delete_user_request(client);

	/* Communicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	if (basic_print_http_response_with_content(response) == -1) {
		basic_print_http_response(response,
			"The usser was deleted successfully.");
	}

	/* Free the memory. */
	free(request);
	free(response);
}

void print_get_users_response(const char* response)
{
	JSON_Value *json_value;
	JSON_Array *users_array;
	JSON_Object *user_object;
	const char *username, *password;
	size_t size;

	json_value = get_json_val_from_string(
		basic_extract_json_response(response)
	);
    users_array = get_json_array_from_json_val(json_value, "users");

	size = json_array_get_count(users_array);
	if (size == 0)
	{
		printf("You do not have users.\n");
	}

    for (size_t i = 0; i < size; i++)
	{
        user_object = json_array_get_object(users_array, i);
		username = json_object_get_string(user_object, "username");
		password = json_object_get_string(user_object, "password");

        printf("#%ld %s:%s\n", i + 1, username, password);
    }

	json_value_free(json_value);
}

void get_users(const client_t *const client)
{
	char *request, *response;
	int ret;
	
	/* Create the request. */
	request = compute_get_request(SRV_IP, SRV_PORT, GET_USERS_URL,
			client->cookie, client->token);

	/* Communicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	ret = basic_print_http_response_with_content(response);
	if (ret == -1)
	{
		ret = basic_print_http_response(response, "Users list:");
	}
	if (ret == 2)
	{
		print_get_users_response(response);
	}

	/* Free the memory. */
	free(request);
	free(response);
}

void get_access(client_t *const client)
{
	char *request, *response;
	
	/* Create the request. */
	request = compute_get_request(SRV_IP, SRV_PORT,
			GET_ACCESS_URL,	client->cookie, client->token
	);

	/* Communicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */;
	get_new_token(client, response);
	if (basic_print_http_response_with_content(response) == -1)
	{
		basic_print_http_response(response, "Received THE JWT token.");
	}

	/* Free the memory. */
	free(request);
	free(response);
}

void print_get_movies_response(const char *response)
{
	JSON_Value *json_value;
	JSON_Array *movies_array;
	JSON_Object *movie_object;
	const char *title;
	size_t id, size;

	json_value = get_json_val_from_string(
		basic_extract_json_response(response)
	);
    movies_array = get_json_array_from_json_val(json_value, "movies");

	size = json_array_get_count(movies_array);
	if (size == 0)
	{
		printf("You do not have movies.\n");
	}

    for (size_t i = 0; i < size; i++)
	{
        movie_object = json_array_get_object(movies_array, i);
		id = json_object_get_number(movie_object, "id");
		title = json_object_get_string(movie_object, "title");

        printf("#%lu %s\n", id, title);
    }

	json_value_free(json_value);
}

void get_movies(const client_t *const client)
{
	char *request, *response;
	int ret;
	
	/* Create the request. */
	request = compute_get_request(SRV_IP, SRV_PORT, GET_MOVIES_URL,
				client->cookie, client->token);

	/* Communicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	ret = basic_print_http_response_with_content(response);
	if (ret == -1)
	{
		ret = basic_print_http_response(response, "Movies list: ");
	}
	if (ret == 2)
	{
		print_get_movies_response(response);
	}

	/* Free the memory. */
	free(request);
	free(response);
}

char *get_get_movie_request(const client_t *const client)
{
	char id[LINELEN];
	char url[2 * LINELEN];
	int ret;

	/* Get the id */
	printf("id=");
	read_line(id, LINELEN);

	/* Complete the url. */
	ret = snprintf(url, sizeof(url), GET_MOVIE_URL, id);
	DIE(ret < 0, "snprintf() failed\n");

	/* Create the request. */
	return compute_get_request(SRV_IP, SRV_PORT, url,
			client->cookie, client->token
	);
}

void print_get_movie_response(const char *response)
{
	char *payload, *pretty_payload;

	payload = basic_extract_json_response(response);
	pretty_payload = get_pretty_string_from_json_string(payload);
	printf("%s\n", pretty_payload);

	free(pretty_payload);
}

void get_movie(const client_t *const client)
{
	char *request, *response;
	int ret;

	/* Create the request. */
	request = get_get_movie_request(client);

	/* Communicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	ret = basic_print_http_response_with_content(response);
	if (ret == -1)
	{
		ret = basic_print_http_response(response, "The movie was found.");
	}
	if (ret == 2)
	{
		print_get_movie_response(response);
	}

	/* Free the memory. */
	free(request);
	free(response);
}

char *get_add_movie_request(const client_t *const client)
{
	char title[LINELEN];
	char year[LINELEN];
	char description[LINELEN];
	char rating[LINELEN];
	char payload[5 * LINELEN];
	int ret;

	/* Get the title. */
	printf("title=");
	read_line(title, sizeof(title));

	/* Get the year. */
	printf("year=");
	read_line(year, sizeof(year));

	/* Get the description. */
	printf("description=");
	read_line(description, sizeof(description));

	/* Get the rating. */
	printf("rating=");
	read_line(rating, sizeof(rating));

	/* Create the payload. */
	ret = snprintf(payload, sizeof(payload), ADD_MOVIE_CONTENT_FORMAT,
			title, year, description, rating
	);
	DIE(ret < 0, "snprintf() failed\n");
	
	/* Create the request. */
	return compute_post_request(SRV_IP, SRV_PORT, ADD_MOVIE_URL,
			ADD_MOVIE_CONTENT_TYPE, payload, client->cookie, client->token
	);
}

void add_movie(const client_t *const client)
{
	char *request, *response;

	/* Create the request. */
	request = get_add_movie_request(client);

	/* Communicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	if (basic_print_http_response_with_content(response) == -1)
	{
		basic_print_http_response(response,
			"Movie added successfully.");
	}

	/* Free the memory. */
	free(request);
	free(response);
}

char *get_delete_movie_request(const client_t *const client)
{
	char id[LINELEN];
	char url[2 * LINELEN];
	int ret;

	/* Get the title. */
	printf("id=");
	read_line(id, sizeof(id));

	/* Complete the url. */
	ret = snprintf(url, sizeof(url), DELETE_MOVIE_URL, id);
	DIE(ret < 0, "snprintf() failed\n");

	/* Create the request. */
	return compute_delete_request(SRV_IP, SRV_PORT, url,
			client->cookie, client->token);
}

void delete_movie(const client_t *const client)
{
	char *request, *response;

	/* Create the request. */
	request = get_delete_movie_request(client);

	/* Communicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	if (basic_print_http_response_with_content(response) == -1)
	{
		basic_print_http_response(response,
			"Movie deleted successfully.");
	}

	/* Free the memory. */
	free(request);
	free(response);
}

char *get_update_movie_request(const client_t *const client)
{
	char id[LINELEN];
	char title[LINELEN];
	char year[LINELEN];
	char description[LINELEN];
	char rating[LINELEN];
	char url[2 * LINELEN];
	char payload[5 * LINELEN];
	int ret;

	/* Get the title. */
	printf("id=");
	read_line(id, sizeof(id));

	/* Complete the url. */
	ret = snprintf(url, sizeof(url), DELETE_MOVIE_URL, id);
	DIE(ret < 0, "snprintf() failed\n");

	/* Get the title. */
	printf("title=");
	read_line(title, sizeof(title));

	/* Get the year. */
	printf("year=");
	read_line(year, sizeof(year));

	/* Get the description. */
	printf("description=");
	read_line(description, sizeof(description));

	/* Get the rating. */
	printf("rating=");
	read_line(rating, sizeof(rating));

	/* Create the payload. */
	ret = snprintf(payload, sizeof(payload), UPDATE_MOVIE_CONTENT_FORMAT,
			title, year, description, rating
	);
	DIE(ret < 0, "snprintf() failed\n");
	
	/* Create the request. */
	return compute_put_request(SRV_IP, SRV_PORT, url,
			UPDATE_MOVIE_CONTENT_TYPE, payload, client->cookie, client->token
	);
}

void update_movie(const client_t *const client)
{
	char *request, *response;

	/* Create the request. */
	request = get_update_movie_request(client);

	/* Communicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	if (basic_print_http_response_with_content(response) == -1)
	{
		basic_print_http_response(response, "Movie updated successfully.");
	}

	/* Free the memory. */
	free(request);
	free(response);
}

char *get_add_movie_to_collection_request(const client_t *const client,
		const char *const coll_id, const char* const movie_id)
{
	char url[2 * LINELEN];
	char payload[2 * LINELEN];
	int ret;

	/* Create the payload. */
	ret = snprintf(payload, sizeof(payload),
			ADD_MOVIE_TO_COLLECTION_CONTENT_FORMAT, movie_id
	);
	DIE(ret < 0, "snprintf() failed\n");

	/* Complete the url. */
	ret = snprintf(url, sizeof(url), ADD_MOVIE_TO_COLLECTION_URL, coll_id);
	DIE(ret < 0, "snprintf() failed\n");

	/* Create the request. */
	return compute_post_request(SRV_IP, SRV_PORT, url,
			ADD_MOVIE_TO_COLLECTION_CONTENT_TYPE, payload,
			client->cookie, client->token
	);

}

void add_movie_to_collection(const client_t *const client,
		const char *const coll_id, const char* const movie_id)
{
	char *request, *response;

	/* Create the requset (our letter to server). */
	request = get_add_movie_to_collection_request(client, coll_id, movie_id);

	/* Comunicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	if (basic_print_http_response_with_content(response) == -1)
	{
		basic_print_http_response(response,
			"Movie added to collection successfully.");
	}

	/* Free the memory. */
	free(request);
	free(response);
}

void add_movies_to_collection(client_t *const client,
		const char *const coll_id)
{
	char movies_num_str[LINELEN];
	char movie_id[LINELEN];
	size_t movies_num_sizet;
	int old_sock_fd, ret;

	/* How many movies do we add? */
	printf("num_movies=");
	read_line(movies_num_str, sizeof(movies_num_str));

	/* Did the client introduce a valid number ? */
	movies_num_sizet = atos(movies_num_str);
	if (movies_num_sizet == SIZE_T_MAX)
	{
		printf("ERROR: Must write an integer number between 0 and %ld\n",
			SIZE_T_MAX);
		return;
	}

	/* Put movies in collection. */
	old_sock_fd = client->sock_fd;
	for (size_t i = 0; i < movies_num_sizet; ++i)
	{
		client->sock_fd = open_connection(SRV_IP, SRV_PORT, AF_INET,
			SOCK_STREAM, 0);

		printf("movie_id[%ld]=", i);
		read_line(movie_id, sizeof(movie_id));

		add_movie_to_collection(client, coll_id, movie_id);

		ret = close(client->sock_fd); /* What was remains in past */
		DIE(ret == -1, "close() failed\n");
	}
	client->sock_fd = old_sock_fd;
}

char *get_add_collection_request(const client_t *const client)
{
	char title[LINELEN];
	char payload[2 * LINELEN];
	int ret;

	/* Get the title. */
	printf("title=");
	read_line(title, sizeof(title));
	
	/* Create the payload. */
	ret = snprintf(payload, sizeof(payload),
			ADD_COLLECTION_CONTENT_FORMAT, title
	);
	DIE(ret < 0, "snprintf() failed\n");

	/* Create the request. */
	return compute_post_request(SRV_IP, SRV_PORT, ADD_COLLECTION_URL,
			ADD_COLLECTION_CONTENT_TYPE, payload, client->cookie,
			client->token
	);

}

void add_collection(client_t *const client)
{
	char *request, *response, *json_response;
	char coll_id[LINELEN];
	int ret;

	/* Create the requset (our letter to server). */
	request = get_add_collection_request(client);

	/* Comunicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	ret = basic_print_http_response_with_content(response);
	if ( ret == -1)
	{
		ret = basic_print_http_response(response,
				"Collection created successfully.");
	}

	/* Add movies in the new created world. */
	if (ret == 2) {
		json_response = basic_extract_json_response(response);

		ret = snprintf(coll_id, sizeof(coll_id), "%ld",
				(size_t) get_number_from_json_string(json_response, "id"));
		DIE(ret == -1, "snprintf() failed\n");
	
		add_movies_to_collection(client, coll_id);
	}

	/* Free the memory. */
	free(request);
	free(response);
}

char *get_delete_collection_request(const client_t *const client)
{
	char coll_id[LINELEN];
	char url[2 * LINELEN];
	int ret;

	/* Get the collection id. */
	printf("id=");
	read_line(coll_id, sizeof(coll_id));

	/* Complete the url. */
	ret = snprintf(url, sizeof(url), DELETE_COLLECTION_URL, coll_id);
	DIE(ret < 0, "snprintf() failed\n");

	/* Create the request. */
	return compute_delete_request(SRV_IP, SRV_PORT, url,
			client->cookie, client->token
	);
}

void delete_collection(const client_t *const client)
{
	char *request, *response;

	/* Create the requset. */
	request = get_delete_collection_request(client);

	/* Comunicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	if (basic_print_http_response_with_content(response) == -1)
	{
		basic_print_http_response(response,
			"Collection deleted successfully.");
	}

	/* Free the memory. */
	free(request);
	free(response);
}

void print_get_collections_response(const char *response)
{
	JSON_Value *json_value;
	JSON_Array *colls_array;
	JSON_Object *coll_object;
	const char *title;
	size_t id, size;

	json_value = get_json_val_from_string(
		basic_extract_json_response(response)
	);
    colls_array = get_json_array_from_json_val(json_value, "collections");

	size = json_array_get_count(colls_array);
	if (size == 0)
	{
		printf("You do not have movies.\n");
	}

    for (size_t i = 0; i < size; i++)
	{
        coll_object = json_array_get_object(colls_array, i);
		id = json_object_get_number(coll_object, "id");
		title = json_object_get_string(coll_object, "title");

        printf("#%lu %s\n", id, title);
    }

	json_value_free(json_value);
}

void get_collections(const client_t *const client)
{
	char *request, *response;
	int ret;

	/* Create the requset. */
	request = compute_get_request(SRV_IP, SRV_PORT, GET_COLLECTIONS_URL,
			client->cookie, client->token
	);

	/* Comunicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	ret = basic_print_http_response_with_content(response);
	if (ret == -1)
	{
		ret = basic_print_http_response(response, "Collections list:");
	}
	if (ret == 2)
	{
		print_get_collections_response(response);
	}

	/* Free the memory. */
	free(request);
	free(response);
}

void print_get_collection_response(const char *response)
{
	char *payload, *title, *owner;

	payload = basic_extract_json_response(response);

	title = get_string_from_json_string(payload, "title");
	printf("title: %s\n", title);
	free(title);

	owner = get_string_from_json_string(payload, "owner");
	printf("owner: %s\n", owner);
	free(owner);

	print_get_movies_response(response);
}

char *get_get_collection_request(const client_t *const client)
{
	char coll_id[LINELEN];
	char url[2 * LINELEN];
	int ret;

	/* Get the collection id. */
	printf("id=");
	read_line(coll_id, sizeof(coll_id));

	/* Complete the url. */
	ret = snprintf(url, sizeof(url), GET_COLLECTION_URL, coll_id);
	DIE(ret < 0, "snprintf() failed\n");

	/* Create the request. */
	return compute_get_request(SRV_IP, SRV_PORT, url,
			client->cookie, client->token
	);
}

void get_collection(const client_t *const client)
{
	char *request, *response;
	int ret;

	/* Create the requset. */
	request = get_get_collection_request(client);

	/* Comunicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	ret = basic_print_http_response_with_content(response);
	if (ret == -1)
	{
		ret = basic_print_http_response(response, "The collection was found.");
	}
	if (ret == 2)
	{
		print_get_collection_response(response);
	}

	/* Free the memory. */
	free(request);
	free(response);
}

char *get_delete_movie_from_collection_request(const client_t *const client)
{
	char coll_id[LINELEN];
	char movie_id[LINELEN];
	char url[2 * LINELEN];
	int ret;

	/* Get the collection id. */
	printf("collection_id=");
	read_line(coll_id, sizeof(coll_id));

	/* Get the +movie id. */
	printf("movie_id=");
	read_line(movie_id, sizeof(movie_id));

	/* Complete the url. */
	ret = snprintf(url, sizeof(url), DELETE_MOVIE_FROM_COLLECTION_URL,
			coll_id, movie_id);
	DIE(ret < 0, "snprintf() failed\n");

	/* Create the request. */
	return compute_delete_request(SRV_IP, SRV_PORT, url,
			client->cookie, client->token
	);
}

void delete_movie_from_collection(const client_t *const client)
{
	char *request, *response;

	/* Create the requset. */
	request = get_delete_movie_from_collection_request(client);
	printf("%s\n", request);

	/* Comunicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	if (basic_print_http_response_with_content(response) == -1)
	{
		basic_print_http_response(response,
			"Movie deleted from collection successfully.");
	}

	/* Free the memory. */
	free(request);
	free(response);
}

void stop_program(client_t *const client)
{
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

bool handle_client_command(client_t *const client, const char *command)
{
	if (!strcmp(command, LOGIN_ADMIN_CMD))
	{
		login_admin(client);
		return true;
	}
	else if (!strcmp(command, LOGIN_CMD))
	{
		login(client);
		return true;
	}
	else if (!strcmp(command, ADD_USER_CMD))
	{
		add_user(client);
		return true;
	}
	else if (!strcmp(command, DELETE_USER_CMD))
	{
		delete_user(client);
		return true;
	}
	else if (!strcmp(command, GET_USERS_CMD))
	{
		get_users(client);
		return true;
	}
	else if (!strcmp(command, GET_ACCESS_CMD))
	{
		get_access(client);
		return true;
	}
	else if (!strcmp(command, LOGOUT_ADMIN_CMD))
	{
		logout_admin(client);
		return true;
	}
	else if (!strcmp(command, LOGOUT_CMD))
	{
		logout(client);
		return true;
	}

	return false;
}

bool handle_movie_command(client_t *const client, const char *command)
{
	if (!strcmp(command, ADD_MOVIE_CMD))
	{
		add_movie(client);
		return true;
	}
	else if (!strcmp(command, DELETE_MOVIE_CMD))
	{
		delete_movie(client);
		return true;
	}
	else if (!strcmp(command, GET_MOVIE_CMD))
	{
		get_movie(client);
		return true;
	}
	else if (!strcmp(command, GET_MOVIES_CMD))
	{
		get_movies(client);
		return true;
	} else if (!strcmp(command, UPDATE_MOVIE_CMD))
	{
		update_movie(client);
		return true;
	}

	return false;
}

bool handle_coll_command(client_t *const client, const char *const command)
{
	if (!strcmp(command, ADD_COLLECTION_CMD))
	{
		add_collection(client);
		return true;
	}
	else if (!strcmp(command, DELETE_COLLECTION_CMD))
	{
		delete_collection(client);
		return true;
	}
	else if (!strcmp(command, ADD_MOVIE_TO_COLLECTION_CMD))
	{
		char coll_id[LINELEN], movie_id[LINELEN];

		/* Get the collection id. */
		printf("collection_id=");
		read_line(coll_id, sizeof(coll_id));

		/* Get the movie id. */
		printf("movie_id=");
		read_line(movie_id, sizeof(movie_id));

		add_movie_to_collection(client, coll_id, movie_id);
		return true;
	}
	else if (!strcmp(command, DELETE_MOVIE_FROM_COLLECTION_CMD))
	{
		delete_movie_from_collection(client);
		return true;
	}
	else if (!strcmp(command, GET_COLLECTION_CMD))
	{
		get_collection(client);
		return true;
	}
	else if (!strcmp(command, GET_COLLECTIONS_CMD))
	{
		get_collections(client);
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
	if (handle_client_command(client, command))
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
