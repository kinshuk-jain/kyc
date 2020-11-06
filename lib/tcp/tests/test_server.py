import pytest
import socket
import threading
import time
import errno
from lib.tcp import eventloop
from lib.tcp import server
from unittest import mock

pytestmark = pytest.mark.lib

HOST_V4 = "127.0.0.1"
HOST_V6 = "::"
HOST = ""
PORT = 5000
io_loop = eventloop.NonBlockingPollFactory.getNonBlockingPoll()

# This test should ideally be first test as if this doesnt work then server wont start
class TestServerBinding:
    def test_server_bindings(self, monkeypatch):
        """test server behavior, sockets and options. It is a very big test"""
        my_mock = mock.Mock()
        dummy = mock.Mock()

        my_mock.poll = mock.Mock(
            return_value=[
                (0, io_loop.READ_EVENT),
                (0, io_loop.WRITE_EVENT),
                (0, io_loop.HUP_EVENT),
                (500, 0),
            ]
        )
        my_mock.accept = mock.Mock(
            side_effect=[
                ConnectionAbortedError("connection aborted"),
                IOError(errno.EAGAIN, "blocked"),
                IOError(errno.EINTR, "interrupted"),
                IOError("exception"),
            ]
        )

        monkeypatch.setattr(eventloop.NonBlockingPoll, "register", dummy.register)
        monkeypatch.setattr(eventloop.NonBlockingPoll, "unregister", dummy.unregister)
        monkeypatch.setattr(eventloop.NonBlockingPoll, "poll", my_mock.poll)
        monkeypatch.setattr(
            server.ProcessManagerFactory, "getProcessManager", lambda: my_mock
        )
        monkeypatch.setattr(server.socket.socket, "setblocking", my_mock.setblocking)
        monkeypatch.setattr(server.socket.socket, "bind", my_mock.bind)
        monkeypatch.setattr(server.socket.socket, "accept", my_mock.accept)
        monkeypatch.setattr(server.socket.socket, "fileno", lambda x: 500)
        monkeypatch.setattr(server.socket.socket, "listen", dummy.listen)
        monkeypatch.setattr(server.socket.socket, "setsockopt", dummy.setsockopt)

        dummy_server = server.TcpServer("", 5001, 10)
        dummy_server.write_response_async = mock.Mock()
        dummy_server.read_request_async = mock.Mock()
        dummy_server.close_client_connection = mock.Mock()
        # we throw a exception in accept method of socket to come out of infinite loop in serve function.
        # for some reason pytest hangs if we use a random exception here
        dummy_server.serve(processes=2)
        expected = []
        if dummy_server.has_ipv6:
            expected = [
                mock.call.fork_processes(2),
                mock.call.setblocking(False),
                mock.call.bind(("0.0.0.0", 5001)),
                mock.call.setblocking(False),
                mock.call.bind(("::", 5001, 0, 0)),
                mock.call.poll(1),
                mock.call.accept(),
                mock.call.poll(1),
                mock.call.accept(),
                mock.call.poll(1),
                mock.call.accept(),
                mock.call.poll(1),
                mock.call.accept(),
                mock.call.kill_process(),
            ]
        else:
            expected = [
                mock.call.fork_processes(2),
                mock.call.setblocking(False),
                mock.call.bind(("0.0.0.0", 5001)),
                mock.call.poll(1),
                mock.call.accept(),
                mock.call.poll(1),
                mock.call.accept(),
                mock.call.poll(1),
                mock.call.accept(),
                mock.call.poll(1),
                mock.call.accept(),
                mock.call.kill_process(),
            ]
        dummy.listen.assert_called_with(10)
        dummy_server.read_request_async.assert_called()
        dummy_server.write_response_async.assert_called()
        dummy_server.close_client_connection.assert_called()
        dummy.register.assert_called_with(500, io_loop.READ_EVENT | io_loop.EXCLUSIVE)
        assert my_mock.mock_calls == expected
        expected = dummy.setsockopt.call_args_list[-2:]
        assert expected[0] == mock.call(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            assert expected[1] == mock.call(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)


class TestServer:
    @classmethod
    def setup_class(cls):
        TestServer.server_obj = server.TcpServer(HOST, PORT, request_queue_size=2)
        t = threading.Thread(
            target=TestServer.server_obj.serve, daemon=True, name="server"
        )
        t.start()

    @pytest.fixture
    def get_client_ipv4(self):
        time.sleep(0.001)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST_V4, PORT))
        yield client
        client.close()

    @pytest.fixture
    def get_client_ipv6(self):
        time.sleep(0.001)
        client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
        client.connect((HOST_V6, PORT, 0, 0))
        yield client
        client.close()

    def test_connect_client_over_ipv4(self, get_client_ipv4, get_client_ipv6):
        """server accepts tcp connections over both ipv4 and ipv6"""
        pass

    def test_server_reads_request(self, get_client_ipv4, get_client_ipv6):
        """server is able to read request over both ipv4 and ipv6"""
        get_client_ipv4.sendall(b"123456")
        get_client_ipv6.sendall(b"123456")

    def test_server_handles_client_hangup(self, get_client_ipv4, get_client_ipv6):
        """server can handle client hangup"""
        [s1, s2] = TestServer.server_obj.get_open_client_connections()[-2:]
        fd1 = s1.fileno()
        fd2 = s2.fileno()
        TestServer.server_obj.start_write(fd1)
        TestServer.server_obj.start_write(fd2)
        s1.close()
        s2.close()
        b = TestServer.server_obj.write_response_async(fd1, b"abcdef")
        a = TestServer.server_obj.write_response_async(fd2, b"abcdef")
        assert a == None
        assert b == None

    def test_server_handles_client_sending_zero_bytes(
        self, get_client_ipv4, get_client_ipv6
    ):
        """server can handle client sending 0 bytes properly"""
        [s1, s2] = TestServer.server_obj.get_open_client_connections()[-2:]
        fd1 = s1.fileno()
        fd2 = s2.fileno()
        TestServer.server_obj.start_write(fd1)
        TestServer.server_obj.start_write(fd2)
        TestServer.server_obj.write_response_async(fd1, b"abcdef")
        TestServer.server_obj.write_response_async(fd2, b"rstuvw")
        data1 = get_client_ipv4.recv(1024)
        data2 = get_client_ipv6.recv(1024)
        assert data1 == b"abcdef"
        assert data2 == b"rstuvw"

    def test_server_handles_client_sending_after_shutdown(
        self, get_client_ipv4, get_client_ipv6
    ):
        """one client misbheaving should not impact other"""
        get_client_ipv4.shutdown(socket.SHUT_RDWR)
        with pytest.raises(Exception):
            get_client_ipv4.send(b"123456")
        get_client_ipv6.sendall(b"123456")

    def test_server_sends_response(self, get_client_ipv4, get_client_ipv6):
        """server is able to send response over both ipv4 and ipv6"""
        [s1, s2] = TestServer.server_obj.get_open_client_connections()[-2:]
        fd1 = s1.fileno()
        fd2 = s2.fileno()
        TestServer.server_obj.start_write(fd1)
        TestServer.server_obj.start_write(fd2)
        len1 = TestServer.server_obj.write_response_async(fd1, b"abcdef")
        len2 = TestServer.server_obj.write_response_async(fd2, b"rstuvw")
        len3 = TestServer.server_obj.write_response_async(fd2, b"")
        data1 = get_client_ipv4.recv(1024)
        data2 = get_client_ipv6.recv(1024)
        assert data1 == b"abcdef"
        assert len1 == 6
        assert len2 == 6
        assert len3 == 0
        assert data2 == b"rstuvw"

    def test_server_does_not_send_data_after_client_conn_closed(self, get_client_ipv4):
        """server no longer sends data to a client socket after connection closed"""
        s = TestServer.server_obj.get_open_client_connections().pop()
        fd = s.fileno()
        s.shutdown(socket.SHUT_RDWR)
        bytes_written = TestServer.server_obj.write_response_async(fd, b"abcdef")
        assert bytes_written == None

    @pytest.mark.parametrize(
        "error",
        [
            OSError(errno.ECONNABORTED, "aborted"),
            OSError(errno.ECONNRESET, "reset"),
            OSError(errno.ETIMEDOUT, "timed out"),
            OSError(errno.EPIPE, "broken pipe"),
            OSError(errno.EAGAIN, "operation would block"),
            OSError(errno.EWOULDBLOCK, "operation would block"),
        ],
    )
    def test_server_handles_errors_on_read(self, monkeypatch, get_client_ipv4, error):
        """server can handle ECONNABORTED, ECONNRESET, ETIMEDOUT, EPIPE, EAGAIN, EWOULDBLOCK"""
        monkeypatch.setattr(socket.socket, "recv", mock.Mock(side_effect=error))
        get_client_ipv4.send(b"123456")

    @pytest.mark.parametrize(
        "error",
        [
            OSError(errno.ECONNABORTED, "aborted"),
            OSError(errno.ECONNRESET, "reset"),
            OSError(errno.ETIMEDOUT, "timed out"),
            OSError(errno.EPIPE, "broken pipe"),
            OSError(errno.EAGAIN, "operation would block"),
            OSError(errno.EWOULDBLOCK, "operation would block"),
        ],
    )
    def test_server_handles_errors_on_write(self, monkeypatch, get_client_ipv4, error):
        """server can handle ECONNABORTED"""
        s = TestServer.server_obj.get_open_client_connections().pop()
        fd = s.fileno()
        monkeypatch.setattr(socket.socket, "send", mock.Mock(side_effect=error))
        TestServer.server_obj.write_response_async(fd, b"abcdef")

    def test_client_socket_is_non_blocking(self, get_client_ipv4):
        """servers socket should be non blocking"""
        s = TestServer.server_obj.get_open_client_connections().pop()
        assert s.getblocking() == False

    def test_server_allows_multiple_requests_over_same_socket(self, get_client_ipv4):
        """server should not close socket after a request/response unless told"""
        s = TestServer.server_obj.get_open_client_connections().pop()
        fd = s.fileno()
        TestServer.server_obj.write_response_async(fd, b"abcdef")
        get_client_ipv4.send(b"123456")
        TestServer.server_obj.write_response_async(fd, b"abcdef")

    def test_close_client_connection_closes_connection(
        self, monkeypatch, get_client_ipv4
    ):
        s = TestServer.server_obj.get_open_client_connections().pop()
        fd = s.fileno()
        # the deletion is needed to remove flakiness in the test
        # this deletion causes underlying file description associated with this socket
        # to be closed as socket close here is mocked
        del s
        monkeypatch.setattr(socket.socket, "close", mock.Mock())
        monkeypatch.setattr(socket.socket, "shutdown", mock.Mock())
        TestServer.server_obj.close_client_connection(fd)
        with pytest.raises(KeyError):
            TestServer.server_obj.write_response_async(fd, b"abcdef")
        assert socket.socket.close.called == True
        assert socket.socket.shutdown.called == True

    def test_tcp_keepalive_on_client_connetion(self, get_client_ipv4):
        s = TestServer.server_obj.get_open_client_connections().pop()
        assert (
            s.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == socket.SO_KEEPALIVE
        )
        # see https://github.com/apple/darwin-xnu/blob/0a798f6738bc1db01281fc08ae024145e84df927/bsd/netinet/tcp.h
        # for meaning of 0x10, 0x101 and 0x102
        assert s.getsockopt(socket.IPPROTO_TCP, 0x10) == 600
        assert s.getsockopt(socket.IPPROTO_TCP, 0x101) == 60
        assert s.getsockopt(socket.IPPROTO_TCP, 0x102) == 5

    def test_remove_all_events(self, monkeypatch):
        dummy = mock.Mock()
        monkeypatch.setattr(eventloop.NonBlockingPoll, "modify", dummy)
        TestServer.server_obj.remove_all_events(12)
        dummy.assert_called_with(12, io_loop.NO_EVENT)
        TestServer.server_obj.start_write(21)
        dummy.assert_called_with(21, io_loop.WRITE_EVENT)
