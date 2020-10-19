from lib.tcp import server
from lib.streams import IOStreamFactory
from .handler import HTTPHandlerFactory

__version__ = "0.1"


class HTTPServer(server.TcpServer):
    """Class creating HTTP server

    Uses TcpServer class. You should NEVER need to use or inherit any of the methods of this class
    except serve
    """

    # stores a list of handlers handling requests
    _handlers = {}

    def _req_ended(self, client_fd):
        """For internal use only. Called when request has ended

        When request ends, remove its file descriptor's interest in read and make it
        only interested in write
        """

        def handler():
            super().finish_read(client_fd)
            # Not interested in pause/end events for request stream
            self._handlers[client_fd].get_request().off("pause")
            self._handlers[client_fd].get_request().off("end")

        return handler

    def _req_paused(self, client_fd):
        """For internal use only. Called when request has paused

        It is a hard requirement that HTTP handler must either pause or end request stream before
        it calls route handlers.
        When request pauses for first time, we know HTTP handler is ready to write response
        but may not be done with request because it has not ended it
        """

        def handler():
            super().start_write(client_fd)
            # Not interested in pause/end events for request stream
            self._handlers[client_fd].get_request().off("pause")

        return handler

    def init_request_async(self, client_conn, client_address):
        """Initialize on incoming request

        Args:
            client_conn: client socket handle
            client_address: client socket address of form (host, port)
        """
        client_fd = client_conn.fileno()
        super().init_request_async(client_conn, client_address)
        # initialize request for this client with an empty string of bytes
        request = IOStreamFactory.getIOStream()
        # client address is a tuple (host, port) or the client
        request.client_address = client_address
        # when request pauses or ends, modify it to be interested only in write events
        request.on("pause", self._req_paused(client_fd))
        request.on("end", self._req_ended(client_fd))
        # attach a handler to this request
        self._handlers[client_fd] = HTTPHandlerFactory.getRequestHandler(request)

    def write_response_async(self, client_fd):
        """Writes response stream to underlying tcp socket

        Args:
            client_fd: file descriptor of client whose request is being read
        """
        # ensure get_response has response available when this is called
        try:
            response = self._handlers[client_fd].get_response()
        except:
            return

        # It is possible that all data cannot be written in one go so we see
        # data and check how much has been written. We drain that much from
        # stream. Also it is possible that response stream might have ended
        # so we only peek and drain. Allows max flexibility
        data = response.peek(server.TCP_WRITE_BUFFER_SIZE)
        if len(data):
            bytes_written = super().write_response_async(client_fd, data)
            response.drain(bytes_written)

        # response stream is ended, we are done
        if response.ended:
            # remove interest in any event
            super().finish_write(client_fd)

            # allow request handler to cleanup by calling close method
            self._handlers[client_fd].close()

            # do not call close as it destroys the socket. Client might want to do additional
            # communication and thus we keep the socket open. Killing this for idle connections
            # is handled by timeouts
            if self._handlers[client_fd].close_connection():
                super().close_client_connection(client_fd)

            # remove handler for this client socket
            del self._handlers[client_fd]

    def read_request_async(self, client_fd):
        """Reads incoming data from tcp socket into a stream

        Args:
            client_fd: file descriptor of client whose request is being read
        """
        request = self._handlers[client_fd].get_request()
        if request.can_write() >= server.TCP_READ_BUFFER_SIZE:
            data = super().read_request_async(client_fd)
            if not data:
                # if no data received after epoll trigger, means client closed connection and
                # cannot receive any more on this socket. We might still be able to send. This
                # can either be due to proper shutdown or due to improper close on client side.
                # If client hangup or error occurs, it will be handled by close_client_connection
                self._handlers[client_fd].client_closed_request()
            else:
                try:
                    # if client is misbehaving and streams dont work as expected
                    # server should not crash, swallow the error
                    request.write(data)
                except:
                    pass

    def close_client_connection(self, client_fd):
        """Close client connection and remove associated references

        Args:
            client_fd: file descriptor of client whose request is being read
        """
        super().close_client_connection(client_fd)

        try:
            if client_fd in self._handlers:
                request = self._handlers[client_fd].get_request()
                request.close()
                response = self._handlers[client_fd].get_response()
                response.close()
                self._handlers[client_fd].close()
                del self._handlers[client_fd]
        except:
            pass

    def serve(self, processes=1):
        """Start the http server

        Args:
            processes: The number of processes that will run this server in parallel
        """
        super().serve(processes=processes)


if __name__ == "__main__":
    # code for tests and logic to run only this module goes here
    pass
