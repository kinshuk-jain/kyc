import pytest
import socket
import select
import os
from lib.tcp import eventloop
from unittest.mock import Mock

pytestmark = pytest.mark.lib


@pytest.fixture
def get_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    yield s
    s.close()


@pytest.fixture
def get_io_loop():
    loop = eventloop.NonBlockingPollFactory.getNonBlockingPoll()
    yield loop
    loop.close()


def test_eventloop_factory(get_io_loop):
    """Event loop factory returns EventLoop objects"""
    assert isinstance(get_io_loop, eventloop.NonBlockingPoll)


def test_register_fd_for_event(get_io_loop, get_socket):
    """registers file descriptors to watch for an event"""
    fd = get_socket.fileno()
    get_io_loop.register(fd, get_io_loop.READ_EVENT)


def test_register_raises_for_unsupported_events(get_io_loop, get_socket):
    """does not register FD for random events"""
    fd = get_socket.fileno()
    with pytest.raises(Exception):
        get_io_loop.register(fd, "blah")


def test_register_raises_for_invalid_fd(get_io_loop):
    """does not register non fd objects"""
    with pytest.raises(Exception):
        get_io_loop.register("blah", get_io_loop.READ_EVENT)


def test_unregister_fd(get_io_loop, get_socket):
    """unregisters fd only"""
    fd = get_socket.fileno()
    get_io_loop.register(fd, get_io_loop.READ_EVENT)
    get_io_loop.unregister(fd)


def test_unregister_raises_on_invalid_fd(get_io_loop, get_socket):
    """does not unregister non fd or when fd not registered"""
    fd = get_socket.fileno()
    get_io_loop.register(fd, get_io_loop.READ_EVENT)
    with pytest.raises(Exception):
        get_io_loop.unregister("blah")


def test_close(get_io_loop):
    """closes for epoll only and for poll does not raise"""
    get_io_loop.close()


def test_is_read_event(get_io_loop):
    """returns True only when event is a read event"""
    if hasattr(select, "EPOLLIN"):
        assert get_io_loop.is_read_event(select.EPOLLIN)
        assert get_io_loop.is_read_event(select.EPOLLPRI)
    else:
        assert get_io_loop.is_read_event(select.POLLIN)
        assert get_io_loop.is_read_event(select.POLLPRI)


def test_is_write_event(get_io_loop):
    """returns True only when an event is a write event"""
    if hasattr(select, "EPOLLIN"):
        assert get_io_loop.is_write_event(select.EPOLLOUT)
    else:
        assert get_io_loop.is_write_event(select.POLLOUT)


def test_is_hup_event(get_io_loop):
    """returns True only when an event is a hup event"""
    if hasattr(select, "EPOLLIN"):
        assert get_io_loop.is_hup_event(select.EPOLLHUP)
    else:
        assert get_io_loop.is_hup_event(select.POLLHUP)


def test_is_error_event(get_io_loop):
    """returns True only when an event is an error event"""
    if hasattr(select, "EPOLLIN"):
        assert get_io_loop.is_err_event(select.EPOLLERR)
    else:
        assert get_io_loop.is_err_event(select.POLLERR)


def test_modify(get_io_loop, get_socket):
    """modifies poll/epoll queue to listen to a new event on fd"""
    fd = get_socket.fileno()
    get_io_loop.register(fd, get_io_loop.READ_EVENT)
    get_io_loop.modify(fd, get_io_loop.WRITE_EVENT)
    # checks if modify can be called multiple times without error
    get_io_loop.modify(fd, get_io_loop.WRITE_EVENT)


def test_modify_fails_for_non_registered_events(get_io_loop, get_socket):
    """modify fails for random events"""
    fd = get_socket.fileno()
    with pytest.raises(Exception):
        get_io_loop.modify(fd, "blah")


def test_modify_fails_for_invalid_fd(get_io_loop, get_socket):
    """modify fails for invalid fd"""
    fd = get_socket.fileno()
    get_io_loop.register(fd, get_io_loop.READ_EVENT)
    with pytest.raises(Exception):
        get_io_loop.modify("blah", get_io_loop.WRITE_EVENT)


def test_poll(get_io_loop):
    """polls file descriptor for events and returns event list"""
    f = open("test.txt", "a")
    get_io_loop.register(f, get_io_loop.WRITE_EVENT)
    [(fd, event)] = get_io_loop.poll(1)
    assert event == get_io_loop.WRITE_EVENT
    assert fd > 2
    os.remove("test.txt")


def test_poll_does_not_block_forever(get_io_loop, get_socket):
    """poll has timeout"""
    fd = get_socket.fileno()
    get_io_loop.register(fd, get_io_loop.READ_EVENT)
    e = get_io_loop.poll(1)
    assert e == [], "events list is empty as polling timedout"
