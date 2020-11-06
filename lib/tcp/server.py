import socket
import select
import errno
import traceback
import sys
from lib.utils import get_errno_from_exception
from lib.process import ProcessManagerFactory
from .eventloop import NonBlockingPollFactory

# value in bytes
TCP_READ_BUFFER_SIZE = 4096
TCP_WRITE_BUFFER_SIZE = 2048


class TcpServer:
    """Creates a TCP server

    Creates a server that listens for incoming requests in non-blocking mode. It also assigns handlers to process
    these requests. The request is transformed to a stream of type streams.Reader and handlers must work with streams.
    Further, handlers must return back a stream of type streams.Writer that will be sent back to client.
    This class supports creation of multiple processes to handle incoming requests thereby using all cores of the system.
    Take care of memory constraints when creating multiple processes as everything is duplicated

    Does not allow simultaneous reads and writes for now. Can either read or write to socket

    TODO: If too many connections arrive, server will be busy accepting requests instead of processing them. So might want to limit number of connections
    """

    # stores all open client connections
    _connections = {}

    def __init__(self, host, port, request_queue_size=5, client_connection_timeout=0):
        """Init

        Args:
            host,port: The address of server where socket will be bound. It includes both host and port
            request_queue_size: The size of socket queue on which connections are accepted by server
            client_connection_timeout: Time in seconds after which client socket will timeout and connection will be closed
        """
        self._host = host
        self._port = port
        self._request_queue_size = request_queue_size
        self._client_connection_timeout = client_connection_timeout

    def has_ipv6(self):
        """Checks whether python and OS support ipv6

        Args:
            None
        Returns:
            True if ipv6 is supported, False otherwise
        """
        if (
            not socket.has_ipv6
            or not hasattr(socket, "IPPROTO_IPV6")
            or not hasattr(socket, "IPV6_V6ONLY")
        ):
            return False
        try:
            # check if underlying OS supports ipv6. If ipv6 is not supported by OS,
            # this socket will raise exception
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                return True
        except:
            return False

    def _create_nonblocking_server(self):
        """For internal use only. Creates a server listener socket that uses epoll/kqueue system calls for non blocking I/O like nodejs

        This function is a wrapper around _create_server function to make the server non blocking.

        Args:
            None
        Returns:
            An list of non blocking sockets that can be used to accept client connections.
        """
        self._non_block_io = NonBlockingPollFactory.getNonBlockingPoll()
        sockets = self._bind_sockets()
        for s in sockets:
            # register all sockets with non blocking IO handler. This will notify
            # when events are available on this socket
            self._non_block_io.register(
                s.fileno(), self._non_block_io.READ_EVENT | self._non_block_io.EXCLUSIVE
            )
        return sockets

    def set_tcp_keepalive(
        self, sock, after_idle_sec=10 * 60, interval_sec=1 * 60, max_fails=5
    ):
        """Set TCP keepalive on an open socket.

        Client side peer that are not sending data or sitting idle must be killed using
        SO_KEEPALIVE after 15m. It activates after 10 minutes (after_idle_sec) of idleness,
        then sends a keepalive ping once every 1 minute (interval_sec), and closes the
        connection after 5 failed ping (max_fails), or 5 minutes. Not needed when sending data
        back to client peer as TCP has a retransmission timeout called RTO. On linux kernel it is
        implemented using exponential backoff and takes 924 seconds(15m approx) before application
        is notified of broken connection. This is exactly what we want
        """
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if sys.platform.startswith("linux"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)
        elif sys.platform.startswith("darwin"):
            TCP_KEEPIDLE = 0x10
            TCP_KEEPINTVL = 0x101
            TCP_KEEPCNT = 0x102
            sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPIDLE, after_idle_sec)
            sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPINTVL, interval_sec)
            sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPCNT, max_fails)

    def _bind_sockets(self):
        """For internal use only. Binds available sockets over ipv4 and ipv6

        This function creates a list of listener socket for our server. If underlying OS supports
        ipv6, then the socket will support both ipv4 and ipv6 connections or otherwise the
        socket will accept only ipv4 connections.

        Args:
            None
        Returns:
            A list of sockets that can be used to accept client connections.
        """
        # emtpy set
        unique_addresses = set()

        # list of available sockets
        sockets = []

        # support connections over both ipv4 and ipv6
        sock_family = socket.AF_UNSPEC

        if not self.has_ipv6():
            # OS has only ipv4 socket
            sock_family = socket.AF_INET

        for res in sorted(
            socket.getaddrinfo(
                self._host,
                self._port,
                sock_family,
                socket.SOCK_STREAM,
                0,
                socket.AI_PASSIVE,
            ),
            key=lambda x: x[0],
        ):
            if res in unique_addresses:
                continue

            unique_addresses.add(res)

            (
                family,
                socktype,
                proto,
                canonname,
                sockaddr,
            ) = res  # pylint: disable=unused-variable
            try:
                #  create socket
                sock = socket.socket(family, socktype, proto)
            except OSError as e:
                # means address family not supported, continue
                if get_errno_from_exception(e) == errno.EAFNOSUPPORT:
                    continue
                raise

            # add reuseaddr option
            # if server needs to be restarted, the same socket might not be available immediately
            # as kernel has not been able to free it due to TIME_WAIT. This line tells kernel to reuse the socket
            # and not throw EADDRINUSE error
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Allow multiple sockets to be bound to same HOST and PORT. With this multiple processes
            # can listen on same socket and only one of them will process it. No 'Thundering Herd'
            if hasattr(socket, "SO_REUSEPORT"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

            # make socket non blocking
            sock.setblocking(False)

            # bind socket to address
            try:
                sock.bind(sockaddr)
                print(
                    "HTTP server started, listening on {address}".format(
                        address=sock.getsockname()
                    )
                )
            except OSError as e:
                if (
                    get_errno_from_exception(e) == errno.EADDRNOTAVAIL
                    and self._host == "localhost"
                    and sockaddr[0] == "::1"
                ):
                    # On some systems (most notably docker with default
                    # configurations), ipv6 is partially disabled:
                    # socket.has_ipv6 is true, we can create AF_INET6
                    # sockets, and getaddrinfo("localhost", ...,
                    # AF_PASSIVE) resolves to ::1, but we get an error
                    # when binding.
                    #
                    # Swallow the error, but only for this specific case.
                    # If EADDRNOTAVAIL occurs in other situations, it
                    # might be a real problem like a typo in a
                    # configuration.
                    print("IPv6 disabled for localhost, it will not be available")
                    sock.close()
                    continue
                else:
                    sock.close()
                    msg = "%s (while attempting to bind on address %r)" % (
                        e.strerror,
                        (self._host, self._port),
                    )
                    raise OSError(get_errno_from_exception(e), msg) from None

            # start listening on the socket
            sock.listen(self._request_queue_size)
            sockets.append(sock)

        # return all sockets available
        return sockets

    def get_open_client_connections(self):
        """Returns a list of open client sockets"""
        return list(self._connections.values())

    def init_request_async(self, client_connection, client_address):
        """Accepts incoming requests by adding them to request pool

        Args:
            client_connection
            client_address
        """
        # make client socket non-blocking
        client_connection.setblocking(0)
        # enable keep alive on client socket
        self.set_tcp_keepalive(client_connection)
        # get client socket file descriptor
        client_fd = client_connection.fileno()
        # register this client fd for non blocking io
        self._non_block_io.register(client_fd, self._non_block_io.READ_EVENT)
        # store the client socket in list of connections
        self._connections[client_fd] = client_connection

    def remove_all_events(self, client_fd):
        """Used to remove interest in any event on poll

        Args:
            client_fd: file descriptor of client socket
        """
        self._non_block_io.modify(client_fd, self._non_block_io.NO_EVENT)

    def start_write(self, client_fd):
        """Called when socket should start writing data

        When ready to send, make client connection socket file descriptor interested
        only in write
        Args:
            client_fd: file descriptor of client connection
        """
        # listen when can we write response
        self._non_block_io.modify(client_fd, self._non_block_io.WRITE_EVENT)

    def _handle_socketio_error(self, client_fd, error):
        """Internal only. Handles error during socket io operation"""
        err_code = get_errno_from_exception(error)
        # means operation would have blocked but this is a non-blocking socket or client crashed or peer socket timed out
        if err_code == errno.EAGAIN or err_code == errno.EWOULDBLOCK:
            pass
        elif (
            err_code == errno.ECONNRESET
            or err_code == errno.ECONNABORTED
            or err_code == errno.ETIMEDOUT
            or err_code == errno.EPIPE
        ):
            self.close_client_connection(client_fd)

    def read_request_async(self, client_fd):
        """Reads incoming bytes

        Args:
            client_fd: file descriptor of client whose request is being read
        Returns:
            data read in bytes
        """
        try:
            # Optimization: read directly into stream buffer using socket.recv_into
            # This helps in not creating a copy of all data received as socket.recv
            # returns bytes. If we read into buffer using memory view, it will be even
            # faster. Problem is buffer will need to be pre-allocated as it's size cannot
            # increase or decrease dynamically with memoryview
            d = self._connections[client_fd].recv(TCP_READ_BUFFER_SIZE)

            # if client sent empty data, means it closed connection. It might still be possible
            # to write, but reading client data is not possible
            if not d:
                self._non_block_io.modify(client_fd, self._non_block_io.NO_EVENT)

            return d
        except OSError as e:
            self._handle_socketio_error(client_fd, e)

    def write_response_async(self, client_fd, data=None):
        """Writes data to socket

        Args:
            client_fd: file descriptor of client whose request is being read
            data: bytes to be written. Must be of type bytes
        Returns:
            size of data written
        """
        try:
            if not data:
                return 0

            # it is possible that all data might not have been written
            return self._connections[client_fd].send(data)
        except OSError as e:
            self._handle_socketio_error(client_fd, e)

    def close_client_connection(self, client_fd):
        """Closes client connection

        Args:
            client_fd; file descriptor of client whose request is being read
        """
        try:
            # see comment below to understand why this is needed. If unregister does not work
            # and for some reason socket is not closed, no epoll event should occur for this
            self._non_block_io.modify(client_fd, self._non_block_io.NO_EVENT)

            # remove the fd from io loop. Note this has no meaning if we dont close socket.
            # If there is even one fd that refers to the underlying file description in epoll set
            # this will not unregister it. Thus sockets must be closed after this
            self._non_block_io.unregister(client_fd)

            # close client connection and delete it
            self._connections[client_fd].shutdown(socket.SHUT_RDWR)
            self._connections[client_fd].close()
            del self._connections[client_fd]
        except:
            # fail silently if closing client connection failed
            pass

    def _handle_poll(self, client_fd, event_code):
        """For internal use only. Handles events from epoll/poll system calls

        Args:
            client_fd: file descriptor of client whose request is being read
            event_code: event_code that triggered this read
        """
        if self._non_block_io.is_read_event(event_code):
            self.read_request_async(client_fd)
        elif self._non_block_io.is_write_event(event_code):
            self.write_response_async(client_fd)
        elif self._non_block_io.is_hup_event(
            event_code
        ) or self._non_block_io.is_err_event(event_code):
            self.close_client_connection(client_fd)

    def serve(self, processes=1):
        """Starts the server that listens on PORT and HOST

        The function to listen to incoming requests using asynchronous I/O. This is a non-blocking server
        Args:
            processes: Number of processes that will accept incoming requests
        """
        try:
            if processes > 1:
                self._process_manager = ProcessManagerFactory.getProcessManager()
                self._process_manager.fork_processes(processes)
            # always create epoll after forking process as otherwise file descriptor to same epoll instance will be duplicated
            # and all of them will watch same socket descriptors. The line below however creates separate socket objects for different processes
            # all connected to same hardware underneath. This creates a problem: When a new connection is received, poll() of
            # individual processes will notify that their socket is ready to accept. But which one of those should accept as all cannot.
            # This problem is present due to level-triggered behavior. In edge triggered, only one gets notified
            # The problem is solved by using EPOLLEXCLUSIVE flag when registering with Epoll.
            # when epoll is not available, it is solved by SO_REUSEPORT flag when creating socket. The only problem with this is when a process
            # dies, it may not be possible to switchover ongoing requests on that process to others which is ok.
            # For systems like Unix/MacOS that dont support both EPOLLEXCLUSIVE and SO_REUSEPORT, we can use mutexes, but since
            # number of processes is gonna be less or equal to number of CPUs, we can simply ignore it even though it leads to wasted CPU cycles
            # on every connection request. Not recommended to do this in production
            all_sockets = self._create_nonblocking_server()
            self._listener_socket_fds = {}
            for s in all_sockets:
                self._listener_socket_fds[s.fileno()] = s

            while True:
                # acquire lock here if implemented
                events = self._non_block_io.poll(1)
                for client_fd, event_code in events:
                    if client_fd in self._listener_socket_fds:
                        try:
                            # accepts incoming requests
                            listener_socket = self._listener_socket_fds[client_fd]
                            connection, address = listener_socket.accept()
                        except ConnectionAbortedError:
                            # ECONNABORTED indicates that there was a connection
                            # but it was closed while still in the accept queue.
                            continue
                        except IOError as e:
                            err_code = get_errno_from_exception(e)
                            # restart 'accept' if it was interrupted
                            if err_code == errno.EINTR or err_code == errno.EAGAIN:
                                continue
                            else:
                                raise
                        # release lock here if implemented, add logic to not
                        # release it multiple times as this is in a loop
                        self.init_request_async(connection, address)
                    else:
                        # release lock here too if implemented, add logic to not
                        # release it multiple times as this is in a loop
                        self._handle_poll(client_fd, event_code)

        except Exception:
            traceback.print_exc()
            print("Exception occurred. Server shutting down ...")

        finally:
            # python will auto cleanup these sockets when server crashes. These are just
            # added for good faith and to show whats going on. Has no performance impact as server
            # is crashing
            # server is going down, OS will auto cleanup client connections
            # so no need to clean them up. It will also reclaim all memory from server
            # so need to delete _requests, _responses, _handlers or _connections
            for fd in self._listener_socket_fds:
                self._non_block_io.unregister(fd)
                self._listener_socket_fds[fd].close()

            # close FDs associated with io
            self._non_block_io.close()

            # kill all processes if parent crashed, otherwise just kill this one
            # actually killing current process is not needed as it's dying anyway
            # this is added just to make sure OS will auto cleanup everything if process
            # dies for any reason
            if hasattr(self, "_process_manager"):
                self._process_manager.kill_process()


if __name__ == "__main__":
    # code for tests and logic to run only this module goes here
    pass

"""
TODO:
1. Use coroutines to handle requests
2. add logging
"""
