#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include "helper.h"
#include "requests.h"
#include "parson.h"
#include "client.h"

/*************************************
 * @brief Initialize the client's info.
 *
 * @param client address in memory
 *************************************/
static void init_client(client_t *const client)
{
	client->sock_fd = -1;
	client->cookie = NULL;
	client->token = NULL;
}

/*************************************
 * @brief Verify if we received a new token from server. If yes, update
 * the client's token.
 *
 * @param client info
 * @param response (of type HTTP) received from server 
 *************************************/
static void get_new_token(client_t *const client, const char *const response)
{
	char *response_payload, *token;

	response_payload = basic_extract_json_response(response);
	token = get_string_from_json_string(response_payload, "token");
	if (token)
	{
		if (client->token)
		{
			free(client->token);
		}
		client->token = token;
	}
}

/*************************************
 * @brief Verify if we received a new cookie from server. If yes, update
 * the client's cookie.
 *
 * @param client info
 * @param response (of type HTTP) received from server 
 *************************************/
static void get_new_cookie(client_t *const client, const char *const response)
{	
	if (strstr(response, "\r\nSet-Cookie:"))
	{
		if (client->cookie)
		{
			free(client->cookie);
		}
		client->cookie = extract_from_http_response(response, "Set-Cookie");
		strtok(client->cookie, "; ");
	}
}

/*************************************
 * @brief This function should only be called on logout. If the server
 * accepted our logout request, we have a new start. The past user / admin
 * leaves and we enter in a state in which we have no client. 
 *
 * @param client info
 * @param response (of type HTTP) received from server 
 *************************************/
static void delete_client_info(client_t *const client,
		const char *const response)
{
	char code[4] = {'\0'};

	get_http_response_code(response, code);
	if (code[0] == '2')
	{
		free(client->cookie);
		client->cookie = NULL;

		free(client->token);
		client->token = NULL;
	}
}

/*************************************
 * @brief Create a HTTP request. Send the request to server. Receive
 * a response from server. Interpretate the answer in a basic mode
 * and print it to stdout.
 *
 * @param client info
 * @param get_funct function which create the request which will be
 * sent to server
 * @param backup_success_msg message which will be printed on success,
 * if the server does not have a field named message in payload 
 *
 * @return the response of the server
 *************************************/
static char *basic_execute_command(const client_t *const client,
		char *(*const get_request)(const client_t *const),
		const char *const backup_success_msg)
{
	char *request, *response;
	
	/* Create the request. */
	request = get_request(client);

	/* Communicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	if (basic_print_http_response_with_content(response) == -1)
	{
		basic_print_http_response(response, backup_success_msg);
	}

	/* Free the memory. */
	free(request);

	return response;
}

/*************************************
 * @brief Create a HTTP get request. Send the request to server. Receive
 * a response from server. Interpretate the answer in a basic mode and
 * print it to stdout.
 *
 * @param client info
 * @param get_funct function which create the request which will be
 * sent to server
 * @param backup_success_msg message which will be printed on success,
 * if the server does not have a field named message in payload 
 * @param print_response function to print the payload of the response,
 * if the request finished with success.
 *************************************/
static void basic_execute_get_command(const client_t *const client,
		char *(*const get_request)(const client_t *const),
		const char *const backup_success_msg,
		void (*const print_response)(const char *const))
{
	char *request, *response;
	int ret;
	
	/* Create the request. */
	request = get_request(client);

	/* Communicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	ret = basic_print_http_response_with_content(response);
	if (ret == -1)
	{
		ret = basic_print_http_response(response, backup_success_msg);
	}
	if (ret == 2)
	{
		print_response(response);
	}

	/* Free the memory. */
	free(request);
	free(response);
}

/*************************************
 * @brief Print an array from the payload of an HTTP response. The format
 * for every element from array is the next one:
 * 		#number value1:value2:value3
 *
 * @param response from server
 * @param array_name from response's payload
 * @param fields which will be printed for every element from array;
 * the first field should store just number; the otehrs must store just
 * strings
 * @param num_fields number of fields printed for every element; must be
 * at least 1
 * @param empty_array_msg that will be used just if the array has 0
 * elements
 *************************************/
static void basic_print_response_with_vector(const char *const response,
		const char *const array_name, const char *const *const fields,
		const size_t num_fields, const char *const empty_array_msg)
{
	JSON_Value *json_value;
	JSON_Array *json_array;
	JSON_Object *json_object;
	size_t size, pos;

	/* Get the array. */
	json_value = get_json_val_from_string(
		basic_extract_json_response(response)
	);
    json_array = get_json_array_from_json_val(json_value, array_name);

	/* Does the array is empty? */
	size = json_array_get_count(json_array);
	if (size == 0)
	{
		printf("%s\n", empty_array_msg);
	}

	/* Print the array alement by element. */
    for (size_t i = 0; i < size; i++)
	{
        json_object = json_array_get_object(json_array, i);

		/* The first subfield */
		printf("#%ld ",
			(size_t ) json_object_get_number(json_object, fields[0])
		);

		/* The middle subfields */
		for (int j = 1; j < num_fields - 1; ++j)
		{
			printf("%s:",
				json_object_get_string(json_object, fields[j])
			);
		}

		/* The last subfields */
		if (num_fields >= 2)
		{
			pos = num_fields - 1;
			printf("%s\n",
				json_object_get_string(json_object, fields[pos])
			);
		}
    }

	/* Free the memory. */
	json_value_free(json_value);
}

static char *get_login_admin_request(const client_t *const client)
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

static void login_admin(client_t *const client)
{
	char *response;

	response = basic_execute_command(client, &get_login_admin_request,
			"Admin logged in successfully.");
	get_new_cookie(client, response);

	free(response);
}

static char *get_logout_admin_request(const client_t *const client)
{
	return compute_get_request(SRV_IP, SRV_PORT, LOGOUT_ADMIN_URL,
				client->cookie, client->token
	);
}

static void logout_admin(client_t *const client)
{
	char *response;

	response = basic_execute_command(client, &get_logout_admin_request,
			"Admin logged out successfully.");
	delete_client_info(client, response);

	free(response);
}

static char *get_login_request(const client_t *const client)
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

static void login(client_t *const client)
{
	char *response;

	response = basic_execute_command(client, &get_login_request,
			"User logged in successfully."
	);
	get_new_cookie(client, response);

	free(response);
}

static char *get_logout_request(const client_t *const client)
{
	return compute_get_request(SRV_IP, SRV_PORT, LOGOUT_URL,
				client->cookie, client->token
	);
}

static void logout(client_t *const client)
{
	char *response;

	response = basic_execute_command(client, &get_logout_request,
			"User logged out successfully."
	);
	delete_client_info(client, response);

	free(response);
}

static char *get_add_user_request(const client_t *const client)
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

static void add_user(const client_t *const client)
{
	free(basic_execute_command(client,
			&get_add_user_request,
			"The user was addes successfully.")
	);
}

static char *get_delete_user_request(const client_t *const client)
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

static void delete_user(const client_t *const client)
{
	free(basic_execute_command(client,
			&get_delete_user_request,
			"The user was deleted successfully.")
	);
}

static void print_get_users_response(const char *const response)
{
	const char *fields[] = {"id", "username", "password"};
	size_t num_fields = sizeof(fields) / sizeof(fields[0]);

	basic_print_response_with_vector(response, "users", fields,
		num_fields , "You do not have users"
	);
}

static char *get_get_users_request(const client_t *const client)
{
	return compute_get_request(SRV_IP, SRV_PORT, GET_USERS_URL,
			client->cookie, client->token
	);
}

static void get_users(const client_t *const client)
{
	basic_execute_get_command(client, &get_get_users_request,
			"Users list:", &print_get_users_response
	);
}

static char *get_get_acces_request(const client_t *const client)
{
	return compute_get_request(SRV_IP, SRV_PORT,
			GET_ACCESS_URL,	client->cookie, client->token
	);
}

static void get_access(client_t *const client)
{
	char *response;

	response = basic_execute_command(client, get_get_acces_request,
			"Received THE JWT token."
	);
	get_new_token(client, response);

	free(response);
}

static void print_get_movies_response(const char *const response)
{
	const char *fields[] = {"id", "title"};
	size_t num_fields = sizeof(fields) / sizeof(fields[0]);

	basic_print_response_with_vector(response, "movies", fields,
		num_fields , "You do not have movies"
	);
}

static char *get_get_movies_request(const client_t *const client)
{
	return compute_get_request(SRV_IP, SRV_PORT, GET_MOVIES_URL,
			client->cookie, client->token
	);
}

static void get_movies(const client_t *const client)
{
	basic_execute_get_command(client, &get_get_movies_request,
			"Movies list:", &print_get_movies_response
	);
}

static char *get_get_movie_request(const client_t *const client)
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

static void print_get_movie_response(const char *const response)
{
	char *payload, *pretty_payload;

	payload = basic_extract_json_response(response);
	pretty_payload = get_pretty_string_from_json_string(payload);
	printf("%s\n", pretty_payload);

	free(pretty_payload);
}

static void get_movie(const client_t *const client)
{
	basic_execute_get_command(client, &get_get_movie_request,
		"The movie was found.", &print_get_movie_response
	);
}

static char *get_add_movie_request(const client_t *const client)
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

static void add_movie(const client_t *const client)
{
	free(basic_execute_command(client,
			&get_add_movie_request,
			"Movie added successfully.")
	);
}

static char *get_delete_movie_request(const client_t *const client)
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

static void delete_movie(const client_t *const client)
{
	free(basic_execute_command(client,
			&get_delete_movie_request,
			"Movie deleted successfully.")
	);
}

static char *get_update_movie_request(const client_t *const client)
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

static void update_movie(const client_t *const client)
{
	free(basic_execute_command(client,
			&get_update_movie_request,
			"Movie updated successfully.")
	);
}

static char *get_add_movie_to_collection_request(const client_t *const client)
{
	char coll_id[LINELEN];
	char movie_id[LINELEN];
	char url[2 * LINELEN];
	char payload[2 * LINELEN];
	int ret;

	/* Get the collection id. */
	printf("collection_id=");
	read_line(coll_id, sizeof(coll_id));

	/* Get the movie id. */
	printf("movie_id=");
	read_line(movie_id, sizeof(movie_id));

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

static void add_movie_to_collection(const client_t *const client)
{
	free(basic_execute_command(client, &get_add_movie_to_collection_request,
		"Movie addes to collection succesfully.")
	);
}

static bool add_movie_to_new_collection(const client_t *const client,
		const char *const coll_id, const char *const movie_id,
		char *const msg)
{
	char *request, *response;
	char url[2 * LINELEN];
	char payload[2 * LINELEN];
	char code[4] = {'\0'};
	int sock_fd, ret;
	bool success;

	/* Create the payload. */
	ret = snprintf(payload, sizeof(payload),
			ADD_MOVIE_TO_COLLECTION_CONTENT_FORMAT, movie_id
	);
	DIE(ret < 0, "snprintf() failed\n");

	/* Complete the url. */
	ret = snprintf(url, sizeof(url), ADD_MOVIE_TO_COLLECTION_URL, coll_id);
	DIE(ret < 0, "snprintf() failed\n");

	/* Create the request. */
	request = compute_post_request(SRV_IP, SRV_PORT, url,
			ADD_MOVIE_TO_COLLECTION_CONTENT_TYPE, payload,
			client->cookie, client->token
	);

	/* Comunicate with the server. */
	sock_fd = open_connection(SRV_IP, SRV_PORT, AF_INET,
			SOCK_STREAM, 0
	);
	send_to_server(sock_fd, request);
	response = receive_from_server(sock_fd);

	/* How did the server answer? */
	get_http_response_code(response, code);
	if (code[0] == '2')
	{
		success = true;
		ret = snprintf(msg + strlen(msg), 100,
			"#%s Added to collection successfully.\n", movie_id
		);
		DIE(ret == -1, "snprintf() failed\n");
	}
	else
	{
		success = false;
		ret = snprintf(msg + strlen(msg), 100,
			"#%s Failed to add to collection.\n", movie_id
		);
		DIE(ret == -1, "snprintf() failed\n");
	}

	/* Free the memory. */
	free(request);
	free(response);
	DIE(close(sock_fd) == -1, "close() failed\n");

	return success;
}

static void add_movies_to_new_collection(const client_t *const client,
		const char *const *const movie_ids, const size_t num_movies,
		const char *const response)
{
	char *msg, *json_response;
	char coll_id[LINELEN];
	bool success;
	int ret;

	/* Allocate memory for the message which will be printed. */
	msg = (char *) malloc(100 * (num_movies + 1));
	DIE(!msg, "malloc() failed\n");
	msg[0] = '\0';

	/* Inform that the collection was created as empty. */
	strcat(msg, "Empty collection created succesfully.\n");

	/* Get the collection's id. */
	json_response = basic_extract_json_response(response);
	ret = snprintf(coll_id, sizeof(coll_id), "%ld",
			(size_t) get_number_from_json_string(json_response, "id")
	);
	DIE(ret == -1, "snprintf() failed\n");

	/* Try to add every movie in collection.
	 * Also, keep the message updated. */
	success = true;
	for (size_t i = 0; i < num_movies; ++i)
	{
		success &= add_movie_to_new_collection(client, coll_id, movie_ids[i], msg);
	}

	/* Print the message. */
	if (success)
	{
		printf("SUCCESS: The collection was created succesfully\n");
	}
	else
	{
		printf("ERROR: Not all movies were added succesfully.\n%s", msg);
	}
}

static char **read_movies_ids(const size_t num_movies)
{
	char **movie_ids;
	
	/* Allocate memory for array. */
	movie_ids = (char **) malloc(num_movies * sizeof(char *));
	DIE(!movie_ids, "malloc() failed\n");

	/* Allocate memory for every element and read it */
	for (size_t i = 0; i < num_movies; ++i)
	{
		movie_ids[i] = (char *) malloc(LINELEN * sizeof(char));
		DIE(!movie_ids[i], "malloc() failed\n");
		
		printf("movie_id[%ld]=", i);
		read_line(movie_ids[i], sizeof(movie_ids[i]));
	}

	return movie_ids;
}

static size_t read_num_movies()
{
	char num_movies_string[LINELEN];
	size_t num_movies_integer;

	/* Read the number of movies*/
	printf("num_movies=");
	read_line(num_movies_string, sizeof(num_movies_string));

	/* Did the client introduce a valid number ? */
	num_movies_integer = atos(num_movies_string);
	if (num_movies_integer == SIZE_T_MAX)
	{
		printf("ERROR: Must select an integer number between 0 and %ld\n",
			SIZE_T_MAX
		);
	}
	return num_movies_integer;
}

static char *get_add_collection_request(const client_t *const client)
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
	char *request, *response;
	size_t num_movies;
	char **movie_ids;
	char code[4] = {'\0'};

	/* Create the requset (our letter to server). */
	request = get_add_collection_request(client);

	/* Read the other fields from stdin. */
	num_movies = read_num_movies();
	if (num_movies == SIZE_T_MAX)
	{
		free(request);
		return;
	}
	movie_ids = read_movies_ids(num_movies);

	/* Comunicate with the server. */
	send_to_server(client->sock_fd, request);
	response = receive_from_server(client->sock_fd);

	/* How did the server answer? */
	get_http_response_code(response, code);
	if (code[0] != '2')
	{
		printf("ERROR: Empty collection could not be creaated.\n");
	}
	else
	{
		add_movies_to_new_collection(client,
			(const char *const *const) movie_ids, num_movies,
			response
		);
	}

	/* Free the memory. */
	free(request);
	free(response);

	for (size_t i = 0; i < num_movies; ++i)
	{
		free(movie_ids[i]);
	}
	free(movie_ids);
}

static char *get_delete_collection_request(const client_t *const client)
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

static void delete_collection(const client_t *const client)
{
	char *response;

	response = basic_execute_command(client, get_delete_collection_request,
			"Collection deleted successfully."
	);

	free(response);
}

static void print_get_collections_response(const char *response)
{
	const char *fields[] = {"id", "title"};
	size_t num_fields = sizeof(fields) / sizeof(fields[0]);

	basic_print_response_with_vector(response, "collections", fields,
		num_fields , "You do not have collections"
	);
}

static char *get_get_collections_request(const client_t *const client)
{
	return compute_get_request(SRV_IP, SRV_PORT, GET_COLLECTIONS_URL,
			client->cookie, client->token
	);
}

static void get_collections(const client_t *const client)
{
	basic_execute_get_command(client, &get_get_collections_request,
		"Collections list:", &print_get_collections_response
	);
}

static void print_get_collection_response(const char *const response)
{
	char *payload, *title, *owner;
	const char *movie_fields[] = {"id", "title"};
	size_t num_fields;

	payload = basic_extract_json_response(response);

	title = get_string_from_json_string(payload, "title");
	printf("title: %s\n", title);
	free(title);

	owner = get_string_from_json_string(payload, "owner");
	printf("owner: %s\n", owner);
	free(owner);

	num_fields = sizeof(movie_fields) / sizeof(movie_fields[0]);
	basic_print_response_with_vector(response, "movies", movie_fields,
		num_fields , "number of movies: 0"
	);
}

static char *get_get_collection_request(const client_t *const client)
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

static void get_collection(const client_t *const client)
{
	basic_execute_get_command(client, &get_get_collection_request,
		"The collection was found.", &print_get_collection_response
	);
}

static char *get_delete_movie_from_collection_request(
		const client_t *const client)
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

static void delete_movie_from_collection(const client_t *const client)
{
	free(basic_execute_command(client,
			&get_delete_movie_from_collection_request,
			"Movie deleted from collection successfully.")
	);
}

static void stop_program(client_t *const client)
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

static bool handle_client_command(client_t *const client, const char *command)
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

static bool handle_movie_command(client_t *const client, const char *command)
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

static bool handle_coll_command(client_t *const client,
		const char *const command)
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
		add_movie_to_collection(client);
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

static void handle_command(client_t *const client) {
	char command[LINELEN];
	int ret;
	
	/* Read command. */
	read_line(command, sizeof(command));

	/* Open connection. */
	client->sock_fd = open_connection(SRV_IP, SRV_PORT, AF_INET,
			SOCK_STREAM, 0
	);

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
