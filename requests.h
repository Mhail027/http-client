#ifndef _REQUESTS_
#define _REQUESTS_

/* Computes and returns a GET request string.
 * (Cookie and token can be NULL if not needed) */
char *compute_get_request(char *ip, int port, char *url,
						  char *cookie, char *token);

/* Computes and returns a POST request string.
 * (Cookie and token can be NULL if not needed) */
char *compute_post_request(char *ip, int port, char *url, char* content_type,
                           char *content, char *cookie, char *token);

char *compute_post_request_1(char *ip, int port, char *url, char* content_type,
						   char *content, char *cookie_1, char *cookie_2, char *token);

#endif
