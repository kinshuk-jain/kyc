### Server

#### General Usage

- The server should be used behind nginx or any reverse proxy
- Reverse proxy will handle tcp timeout, http keep-alive, http/2.0 and ssl termination
- To make this server front facing without reverse proxy we will need http/2.0, http keep-alive and ssl termination
  at least. We will also need to put in extra security features to prevent attacks. Thus is it not recommended


#### Features

- Handles HTTP/1.0 and HTTP/1.0
- Handles TCP keep alive which is set to 15m
- It is based on Epoll/Poll with non-blocking sockets
- Does not support HTTP Trace
- Does not support keep-alive for HTTP/1.0
- Does not support HTTP/2.0
- Does not support http keep-alive timeout
- Does not support multiple compression in content-encoding header
- Does not handle SSL

Most of the unsupported features can be handled by a reverse proxy like nginx
