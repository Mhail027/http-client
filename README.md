README
====

***Title: HTTP Client***

**Author: Necula Mihail**

**Group: 323CAa**

**University year: 2024 - 2025**

---

Chapter 1 - The commands' implementation
====

<img src="media/frozen.jpeg" style="float: left; margin-right: 20px; width: 330px;">

In total, the client can use 20 commands, which can be seen in the file "client.h". 19
of the 20 follow a similar pattern:
    1. Create a HTTP request. (In some cases, ask additional information to
       complete the request.)
    2. Communicate with the server. (Send the request. + Receive an answer.)
    3. Print a basic message to resume the received response. The message has
       always the format "ERROR: %s" or "SUCCESS: %s".
    4. Print more specific data from response if it's the case. We need this step
       for commands such as "get_users", "get_movie", "get_movies" and so on.
</pre>

<pre style="font-family: inherit; font-size: inherit; line-height: inherit; color: inherit; background: transparent; border: none">
The only command that needs special attention is "add_collection". This happens
because, to complete it, we need to send more requests to server. We will follow
the previous pattern, but we will go trough it more times. In this case, the forth
step does not exit. More, in the third one, we do not print the messages immediately.
We stack them in a buffer and print them together with an only label of type ERROR /
SUCCESS, at the final of the command's execution.

If would have been my choice, i would have printed after every movie's id introduced,
if it was added in collection or not. Unfortunately, the checker does not let this to
happen and I can not change its behavior (at least for now). So, the only solution was
to stack the messages for this command, "add_collection". 
</pre>

---

Chapter 2 - Flow of the program
====

```
The function basic_execute_command(), which implement the common pattern, has the next flow:
		basic_execute_command() -> get_request() -> read_line(), sometimes
								-> send_to_server()
								-> receive_from_server()
								-> basic_print_http_response_with_content()
								-> basic_print_http_response()
								-> print_response()
```

```
LOGIN_ADMIN:
	main() -> handle_command() -> handle_client_command() ->
	-> login_admin() -> basic_execute_command()
					 -> get_new_cookie()
```

```
LOGOUT_ADMIN:
	main() -> handle_command() -> handle_client_command() ->
	-> logout_admin() -> basic_execute_command()
					  -> delete_client_info()
```

```
LOGIN:
	main() -> handle_command() -> handle_client_command() ->
	-> login() -> basic_execute_command()
	 		   -> get_new_cookie()
```

```
LOGOUT_ADMIN:
	main() -> handle_command() -> handle_client_command() ->
	-> logout() -> basic_execute_command()
			    -> delete_client_info()
```

```
GET_ACCESS
	main() -> handle_command() -> handle_client_command() ->
	-> get_access() -> basic_execute_command()
				    -> get_new_token()
```

```
ADD_COLLECTION()
	main() -> handle_command() -> handle_coll_command() ->
	-> add_collection() -> read_num_movies()
					    -> read_movies_ids()
					    -> add_movies_to_new_collection() -> add_movie_to_new_collection()
```

```
All the others commands follow the next "road":
	main() -> handle_command() -> handle_client_command() /
	handle_movie_command() / handle_coll_command() ->
	-> name_of_the_command() -> basic_execute_command()
```

---

Chapter 3 - The JSON library
====

<pre style="font-family: inherit; font-size: inherit; line-height: inherit; color: inherit; background: transparent; border: none">

To handle the JSON payloads, we used the Parson library. This one is not needed
when we create the JSONs. We have all the JSON formats for this process in the
file "client.h". The reason for which we included this library is to parse the
payloads from the server's responses. We use Parson for the next 4 things:
	-> to extract the value of a string field
	-> to extract the value of a number field
	-> to obtain pretty strings that can be understood easily
	-> to take the value of an array field and to iterate through that vector 
</pre>

---
