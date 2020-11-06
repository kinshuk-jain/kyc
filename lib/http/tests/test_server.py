import pytest
import threading
import time
import socket
from unittest import mock
from lib import streams
from lib.http import server as http
from lib.tcp import server as tcp

pytestmark = pytest.mark.lib

HOST = "127.0.0.1"
PORT = 6000


class TestHttpServer:
    @classmethod
    def setup_class(cls):
        TestHttpServer.server_obj = http.HTTPServer(HOST, PORT, request_queue_size=2)

    def test_http_server_is_of_type_tcp(self):
        assert isinstance(TestHttpServer.server_obj, tcp.TcpServer)

    def test_http_overrides_and_calls_init(self, monkeypatch):
        fd = 123
        req_mock = mock.Mock()
        res_mock = mock.Mock()
        req_mock.fileno = mock.Mock(return_value=fd)
        iostream_mock = mock.Mock(side_effect=[req_mock, res_mock])

        any_mock = mock.Mock()
        server_mock = mock.Mock()
        handler_mock = mock.Mock()
        handler_mock.get_request = mock.Mock(return_value=req_mock)

        monkeypatch.setattr(
            http.server.TcpServer, "init_request_async", server_mock.init_request_async
        )
        monkeypatch.setattr(http.HTTPHandlerFactory, "getRequestHandler", handler_mock)
        monkeypatch.setattr(http.IOStreamFactory, "getIOStream", iostream_mock)
        monkeypatch.setattr(
            http.server.TcpServer, "remove_all_events", server_mock.remove_all_events
        )

        TestHttpServer.server_obj.init_request_async(req_mock, any_mock)

        server_mock.init_request_async.assert_called_once_with(req_mock, any_mock)
        handler_mock.assert_called_once_with(req_mock, res_mock)
        assert req_mock.client_address == any_mock
        assert res_mock._start_response == TestHttpServer.server_obj.start_write
        assert res_mock.client == req_mock
        args, kwargs = req_mock.on.call_args
        assert args[0] == "end"
        args[1]()
        server_mock.remove_all_events.assert_called_once_with(fd)

    def test_http_overrides_and_calls_tcp_read(self, monkeypatch):
        fd = 123
        read_mock = mock.Mock(return_value=b"123456")
        req_mock = mock.Mock()
        req_mock.fileno = mock.Mock(return_value=fd)
        req_mock.can_write = mock.Mock(return_value=tcp.TCP_READ_BUFFER_SIZE + 1)
        iostream_mock = mock.Mock(return_value=req_mock)

        monkeypatch.setattr(http.server.TcpServer, "init_request_async", mock.Mock())
        monkeypatch.setattr(http.server.TcpServer, "read_request_async", read_mock)
        monkeypatch.setattr(http.IOStreamFactory, "getIOStream", iostream_mock)

        TestHttpServer.server_obj.init_request_async(req_mock, mock.Mock())
        TestHttpServer.server_obj.read_request_async(fd)

        assert req_mock.can_write.called == True
        req_mock.write.assert_called_once_with(b"123456")
        assert read_mock.called == True
        read_mock.assert_called_with(fd)

        monkeypatch.setattr(
            http.server.TcpServer, "read_request_async", mock.Mock(return_value=b"")
        )
        TestHttpServer.server_obj.read_request_async(fd)
        req_mock.end.assert_called()

    def test_http_close_client_connection(self, monkeypatch):
        dummy_server = mock.Mock()
        any_mock = mock.Mock()

        res_mock = mock.Mock()
        res_mock.fileno = mock.Mock(return_value=123)

        iostream_mock = mock.Mock(return_value=res_mock)

        monkeypatch.setattr(
            http.HTTPHandlerFactory,
            "getRequestHandler",
            lambda *args, **kwargs: any_mock,
        )
        monkeypatch.setattr(
            http.server.TcpServer, "init_request_async", dummy_server.init_request_async
        )
        monkeypatch.setattr(
            http.server.TcpServer,
            "close_client_connection",
            dummy_server.close_client_connection,
        )
        monkeypatch.setattr(http.IOStreamFactory, "getIOStream", any_mock)

        TestHttpServer.server_obj.init_request_async(res_mock, mock.Mock())
        TestHttpServer.server_obj.close_client_connection(123)

        dummy_server.close_client_connection.assert_called_once_with(123)
        any_mock.close.assert_called()

    def test_http_overrides_and_calls_tcp_write(self, monkeypatch):
        fd = 123
        write_mock = mock.Mock(return_value=4)
        res_mock = mock.Mock()
        res_mock.is_empty = mock.Mock(return_value=False)
        res_mock.fileno = mock.Mock(return_value=fd)
        res_mock.peek = mock.Mock(return_value=b"123456")

        handler_mock = mock.Mock()
        handler_mock.get_response = mock.Mock(return_value=res_mock)
        handler_mock.close_connection = mock.Mock(return_value=True)

        monkeypatch.setattr(
            http.HTTPHandlerFactory,
            "getRequestHandler",
            lambda *args, **kwargs: handler_mock,
        )
        monkeypatch.setattr(http.server.TcpServer, "init_request_async", mock.Mock())
        monkeypatch.setattr(http.server.TcpServer, "write_response_async", write_mock)
        monkeypatch.setattr(
            http.server.TcpServer, "remove_all_events", write_mock.remove_all_events
        )
        monkeypatch.setattr(
            http.server.TcpServer,
            "close_client_connection",
            write_mock.close_client_connection,
        )
        monkeypatch.setattr(http.IOStreamFactory, "getIOStream", mock.Mock())

        TestHttpServer.server_obj.init_request_async(res_mock, mock.Mock())
        TestHttpServer.server_obj.write_response_async(fd)

        res_mock.peek.assert_called_once_with(tcp.TCP_WRITE_BUFFER_SIZE)
        res_mock.drain.assert_called_once_with(4)
        write_mock.assert_called_once_with(fd, b"123456")

        res_mock.is_empty = mock.Mock(return_value=True)
        TestHttpServer.server_obj.write_response_async(fd)

        write_mock.remove_all_events.assert_called_once_with(fd)
        handler_mock.close_connection.assert_called()
        write_mock.close_client_connection.assert_called_once_with(fd)


# removes handler from req stream on end
