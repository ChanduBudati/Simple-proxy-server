# Simple-proxy-server

When a new client initiates a TCP connection request, the daemon accepts the request and establishes a new TCP connection with the new client.
(a) The daemon forks a child process that is dedicated to handling the new client.
(b) The child process establishes a newTCP connection to a pre-assigned port on the actual targeted server.
(c) The child process falls into a loop in which it acts as an intermediator exchanging data (reading/writing or writing/reading) between the client and the targeted server.
(3) Once a child has been forked, the daemon process resumes listening for additional TCP connections.
2. Requirements
(a) You may treat this project as an individual project or form a project team of no more than 2 members.
(b) You are given the flexibility to choose one of your favorite programming languages for implementation either in Windows or Linux environment.
Note: C language is usually preferred for network programming.
