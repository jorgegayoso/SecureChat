Secure Programming Assignment Documentation 

> Overview of each type of messages exchanged between client and server, including whether cryptography is applied and how

--- DATABASE OVERVIEW ---

USERS
|--------------------------------------------------------|
| username TEXT PRIMARY KEY | password TEXT | online INT |
|--------------------------------------------------------|

MESAGES
|--------------------------------------------------------------------------------------------|
| id INTEGER PRIMARY KEY AUTOINCREMENT | time TEXT | user TEXT | privacy TEXT | message TEXT |
|--------------------------------------------------------------------------------------------|


--- Server ---
Upon initialization, server has:
 - serverkeys folder
	- Its own SSL certificate
	- Its own SSL key
 - chat.db (creates it if does not exist)
	- Contains users database
	- Contains chat history
 - Reference to trusted 3rd party (not implemented)

--- reliance on workers ---
The server's main purpose is to handle connections by creating and managing workers, and occasionally initialize/update databases. 

--- server inintialization ---
Upon initialization, server updates itself with its SSL certificate, then attempts to access the chat.db file. If the database does not exist, it creates the database.
Server starts listening for connections.

--- Connection with client ---
Each time a client connects, the server forks and creates a worker dedicated to the connection to that client instance. Client count is updated. (Client not allowed to connect if client count is over the limit)



--- Client ---

Upon initialization, client has:
 - clientkeys folder
	 - Server's SSL certificate
 - Its own public key (not implemented)
 - Its own private key (not implemented)
 - Reference to trusted 3rd party


--- Client initialization ---
Upon initialization, the client attempts to connect to the server through a worker instance. This is done using client_connect(). Within this function, the client connects to the server through the socket, and the server is verified using the SSL connection. If the connection fails, the server or SSL certificate is compromized and the client exits. 

--- Client-to-Server communication ---
All messages sent to the server (written to the shared socket) is encrypted using the server's SSL certificate.

--- Client termination ---
Ends the connection, frees memory associated with client state, and ends the client instance.



--- Worker ---
Upon initialization, worker has:
 - Everything server has

--- Handling of client commands ---

Message types

- Public message
- Private message
- Commands:
	- /register
	- /login
	- /logout


--- Trusted 3rd Party ---
Consists of a Python script that generate key pairs. Once a client registers (a user logs in) the python script is called and a key pair is generated for the respective user the client is servicing. Creates the folders "clientkeys", "serverkeys"and  "ttpkeys" if they dont exist already


> An overview of your approach to key distribution (not implemented)
How to implement:
For key distribution, we would use RSA encryption to encrypt the symmetric key ussed to encrypt the message to be sent. Symmetric encryption is faster than RSA, so we would pass around keys using RSA. 


--- Example runs of the program ---
Client start -> client connects to server -> client makes RSA keys -> client sends RSA public key to server

Example of the use of keys when sending a message:
Client A wants to send private message to Client B
1. Client A encrypts plaintext with Client B's public key
2. Client A sends encrypted message to server via SSL
3. Server receives encrypted message
4. Server decrypts message using SSL key
5. Server recognizes it is a private message command, and prepares the correct message response / message to send to client B
5. Server sends encrypted message to Client B via SSL
6. Client B receives encrypted message
7. Client B decrypts message using Client B's private key




> An explanation of how this addresses the requirements in section 7

----- Server-Client Communication -----

-> Server-client interactions:
- Interactions between the server and the client happen through workers.
When a client connects to the server it will be assigned a worker. 
All further interactions will only involve the client and its assigned worker.
The worker will only take care of this client. 

- Whenever a worker needs to call all other workers, it will do so through the server.The worker uses the "SSL_write()" function to signal the server. The server then uses the "SSL_read()" function to receive the call and access all workers. 	
		 
-> Packet Data Layout:

- The client waits for an input from "stdin", and when given, it will store it as a "char*" and use "strcmp()" to check for the "/exit" command. If it is, the  nm, application will terminate. If it isn't, then it will send the given "char*" to the corresponding worker via the function "api_send()". 

- Once a worker receives a client request through "api_recv()" it will process it and reply with the appropriate response "char*". 
Once the client receives the message, it will print it to "stdout". 

- Both the data sent from the client to the worker and from the worker to the client are a "char*" with a maximum of 256 characters. The new line character from the "stdin" input is removed.

Security Goals:

Security Requirements
- Private messages sent to the server by the user that wants to send the private message are encrypted using the server's SSL certificate. Even if Mallory intercepts the message, she will not be able to decrypt it since she does not have the server's SSL key.

- The only way for Mallory to send a message on behalf of another user would be if Mallory managed to get the username and password of the user in question. The passwords would be encrypted using SHA-2.

- The only way for Mallory to modify messages is if she had direct access to and had write privileges on the chat’s save file.

- Password hashing will be used to avoid compromising passwords, using SHA-2 as the secure hashing algorithm. Private keys are not stored in the server, therefore even if it's compromised, Mallory won't be able to access them.
		
- By using SSL, we avoid any tampering, evesdropping or corruption of data by a hacker.  SSL employs cryptographic hash functions and message authentication codes to ensure data integrity. This means that if any part of the encrypted data is altered during transmission, the server will be able to detect it, and the data will be considered compromised.

- To avoid crashes in the client we will Implement bound checking to avoid buffer overflows. Use safe string manipulation functions such as” strncpy()” that also perform bound checking to prevent buffer overflows.

Potential Attacks: 
- Attacker may try to modify, leak or corrupt data being sent from client to server and from server to client
	- The attacker may try to get information from private messages
	- The attacker may try to impersonate another user by sending a message on their behalf.
	- The attacker may try to obtain private keys from users and/or servers.
	- The attacker may try to crash the server or client.

User BOB logs into client A. Worker A is assigned to client A. 
Server only takes messages from BOB from worker A.
User BOB also logs into client B. Worker B is assigned to client B. 
Server only takes messages from BOB from worker A and worker B.

Once a new user is registered, a salt is created and added to the user's raw password to create a hash. The username, salt and hash are stored in a database. When a user tries to log in, the password given will be encrypted using the user’s hash, and if this hash is the same as the one stored in the database, the user has entered the password correctly.
