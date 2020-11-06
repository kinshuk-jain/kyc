### Server

- The server should be used behind nginx
- Nginx will handle tcp timeout, http keep-alive, http/2.0, ssl termination
- To make this server front facing without nginx we will need http/2.0, http keep-alive and ssl termination
  at least. We will also need to put in extra security features to prevent attacks

