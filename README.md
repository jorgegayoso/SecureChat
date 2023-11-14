Secure Programming Assignment Documentation 

----- Server-Client Communication -----

	-> Server-client interactions:
		- Interactions between the server and the client happen through workers.
		When a client connects to the server it will be assigned a worker. 
		All further interactions will only involve the client and its assigned worker.
		The worker will only take care of this client. 

		- Whenever a worker needs to call all other workers, it will do so through the server.
		The worker uses the "write()" function to signal the server. The server then uses the "read()"
		function to receive the call and access all workers. 
		 

	-> Packet Data Layout:

		- The client waits for an input from "stdin", and when given, it will store it as a "char*"
    and use "strcmp()" to check for the "/exit" command. If it is, the  nm, napplication will 
    terminate. If it isnt, then it will send the given "char*" to the corresponding worker
		via the function "api_send()". 

		- Once a worker receives a client request through "api_recv()" it will process it and 
    reply with the appropriate response "char*". 
		Once the client receives the message, it will print it to "stdout". 

		- Both the data sent from the client to the worker and from the worker to the client are a "char*
    " with a maximum of 256 characters. The new line character from the "stdin" input is removed.

	-> Cryptography: N/A (Cryptography has not been implemented yet)

----------- Security Goals ------------

	-> Potential Attacks: N/A

	-> Security Properties: N/A
