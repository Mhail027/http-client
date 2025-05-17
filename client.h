#ifndef _CLIENT_
#define _CLIENT_

/* Structure to save the client's info. */
typedef struct client_t {
	int sock_fd;
	char *cookie;
	char *token;
} client_t;

/* Server's info */
#define SRV_IP "63.32.125.183"
#define SRV_PORT 8081

/* Version of http connection */
#define HTTP_VRS "HTTP/1.1"

/* Comands names */
#define LOGIN_ADMIN_CMD "login_admin"
#define ADD_USER_CMD "add_user"
#define GET_USERS_CMD "get_users"
#define DELETE_USER_CMD "delete_user"
#define LOGIN_CMD "login"
#define GET_ACCESS_CMD "get_access"
#define GET_MOVIES_CMD "get_movies"
#define GET_MOVIE_CMD "get_movie"
#define ADD_MOVIE_CMD "add_movie"
#define DELETE_MOVIE_CMD "delete_movie"
#define UPDATE_MOVIE_CMD "update_movie"
#define GET_COLLECTIONS_CMD "get_collections"
#define GET_COLLECTION_CMD "get_collection"
#define ADD_COLLECTION_CMD "add_collection"
#define DELETE_COLLECTION_CMD "delete_collection"
#define ADD_MOVIE_TO_COLLECTION_CMD "add_movie_to_collection"
#define DELETE_MOVIE_FROM_COLLECTION_CMD "delete_movie_from_collection"
#define LOGOUT_ADMIN_CMD "logout_admin"
#define LOGOUT_CMD "logout"
#define EXIT_CMD "exit"

/* Server's urls */
#define LOGIN_ADMIN_URL "/api/v1/tema/admin/login"
#define ADD_USER_URL "/api/v1/tema/admin/users"
#define GET_USERS_URL "/api/v1/tema/admin/users"
#define DELETE_USER_URL "/api/v1/tema/admin/users/%s" /* username */
#define LOGIN_URL "/api/v1/tema/user/login"
#define GET_ACCESS_URL "/api/v1/tema/library/access"
#define GET_MOVIES_URL "/api/v1/tema/library/movies"
#define GET_MOVIE_URL "/api/v1/tema/library/movies/%s" /* movie id*/
#define ADD_MOVIE_URL "/api/v1/tema/library/movies"
#define DELETE_MOVIE_URL "/api/v1/tema/library/movies/%s" /* movie id*/
#define UPDATE_MOVIE_URL "/api/v1/tema/library/movies/%s" /* movie id*/
#define GET_COLLECTIONS_URL "/api/v1/tema/library/collections"
#define GET_COLLECTION_URL "/api/v1/tema/library/collections/%s" /* coll id */
#define ADD_COLLECTION_URL "/api/v1/tema/library/collections"
#define LOGOUT_ADMIN_URL "/api/v1/tema/admin/logout"
#define LOGOUT_URL "/api/v1/tema/user/logout"
#define DELETE_COLLECTION_URL												\
	"/api/v1/tema/library/collections/%s" /* coll id */
#define ADD_MOVIE_TO_COLLECTION_URL											\
	"/api/v1/tema/library/collections/%s/movies" /* coll id*/
#define DELETE_MOVIE_FROM_COLLECTION_URL									\
	"/api/v1/tema/library/collections/%s/movies/%s" /* coll id, movie id*/

/* HTTP Content Types*/
#define LOGIN_ADMIN_CONTENT_TYPE "application/json"
#define ADD_USER_CONTENT_TYPE "application/json"
#define LOGIN_CONTENT_TYPE "application/json"
#define ADD_MOVIE_CONTENT_TYPE "application/json"
#define UPDATE_MOVIE_CONTENT_TYPE "application/json"
#define ADD_COLLECTION_CONTENT_TYPE "application/json"
#define ADD_MOVIE_TO_COLLECTION_CONTENT_TYPE "application/json"

/* HTTP Content formats */
#define LOGIN_ADMIN_CONTENT_FORMAT											\
	"{"																		\
		"\"username\":\"%s\","												\
		"\"password\":\"%s\""												\
	"}"
#define ADD_USER_CONTENT_FORMAT												\
	"{"																		\
		"\"username\":\"%s\","												\
		"\"password\":\"%s\""												\
	"}"
#define LOGIN_CONTENT_FORMAT												\
	"{"																		\
		"\"admin_username\":\"%s\","										\
		"\"username\":\"%s\","												\
		"\"password\":\"%s\""												\
	"}"
#define ADD_MOVIE_CONTENT_FORMAT											\
	"{"																		\
		"\"title\":\"%s\","													\
		"\"year\":%s,"														\
		"\"description\":\"%s\","											\
		"\"rating\":%s"														\
	"}"
#define UPDATE_MOVIE_CONTENT_FORMAT											\
	"{"																		\
		"\"title\":\"%s\","													\
		"\"year\":%s,"														\
		"\"description\":\"%s\","											\
		"\"rating\":%s"														\
	"}"
#define ADD_COLLECTION_CONTENT_FORMAT										\
	"{"																		\
		"\"title\":\"%s\""													\
	"}"
#define ADD_MOVIE_TO_COLLECTION_CONTENT_FORMAT								\
	"{"																		\
		"\"id\":%s"															\
	"}"

#endif
