"""You should never need to change this module"""

import select


class NonBlockingPoll:
    """Implementation of poll/epoll to listen to events that occur on file descriptors

    For more info - https://www.ulduzsoft.com/2014/01/select-poll-epoll-practical-difference-for-system-architects/#:~:text=It%20is%20more%20complex%20to,descriptors%20which%20triggered%20the%20events
    This class is tightly coupled with TcpServer and is not meant to be used otherwise
    """

    def __init__(self):
        try:
            # Epoll: supported only in Linux 2.5.44 or higher
            # it scales better than poll() system call
            # By default it runs in level-triggered mode.
            # Level triggered mode means on every poll, kernel checks if input is available or output can be sent on a file descriptor.
            # Our application can choose to do nothing or read/send partial data. On next poll, kernel will notify again that data is available as
            # complete data has not been read. Thus, kernel is repeatedly notifying about file descriptors that have not finished I/O.
            # In edge-triggered mode, kernel notifies when data is available or can be sent only once. If we do not consume all data available or send
            # all data, it will hang. Thus edge-triggered mode is faster as kernel does not need to keep track of file descriptors that have been partially consumed
            # If performance of this server is to be improved, edge-triggered can be considered. It is more complex
            self.epoll = select.epoll()  # pylint: disable=no-member
            # triggered when data is available from peer socket on receive buffer
            self.READ_EVENT = (
                select.EPOLLIN | select.EPOLLPRI
            )  # pylint: disable=no-member
            # triggered when data has been sent to peer socket from send buffer
            self.WRITE_EVENT = select.EPOLLOUT  # pylint: disable=no-member
            # triggered when socket hangs up
            self.HUP_EVENT = select.EPOLLHUP  # pylint: disable=no-member
            # triggered when socket errors
            self.ERROR_EVENT = select.EPOLLERR  # pylint: disable=no-member
            # Read TcpServer.serve function to understand its use
            self.EXCLUSIVE = select.EPOLLEXCLUSIVE  # pylint: disable=no-member
            self.NO_EVENT = 0
        except:
            # supported by all Unix/Linux systems though not best for BSD systems where kqueue() is better
            self.epoll = select.poll()
            self.READ_EVENT = select.POLLIN | select.POLLPRI
            self.WRITE_EVENT = select.POLLOUT
            self.HUP_EVENT = select.POLLHUP
            self.ERROR_EVENT = select.POLLERR
            # not available in poll
            self.EXCLUSIVE = 1
            self.NO_EVENT = 0

    def register(self, fd, event):
        """Register file descriptors interest in event

        Args:
            fd: filedescriptor to watch
            event: event to watch for
        """
        self.epoll.register(fd, event)

    def unregister(self, fd):
        """Unregister file descriptors interest in any event

        Args:
            fd: filedescriptor to unregister
        """
        self.epoll.unregister(fd)

    def close(self):
        """Close all non block io

        Close is only supported by epoll and not poll
        """
        if hasattr(select, "EPOLLIN"):
            self.epoll.close()

    def is_read_event(self, code):
        """checks if event code passed is a read event

        Args:
            code: event code
        Returns:
            True if read event, false otherwise
        """
        return code & self.READ_EVENT

    def is_write_event(self, code):
        """checks if event code passed is a write event

        Args:
            code: event code
        Returns:
            True if write event, false otherwise
        """
        return code & self.WRITE_EVENT

    def is_hup_event(self, code):
        """checks if event code passed is a hangup event

        Args:
            code: event code
        Returns:
            True if hangup event, false otherwise
        """
        return code & self.HUP_EVENT

    def is_err_event(self, code):
        """checks if event code passed is an error event

        Args:
            code: event code
        Returns:
            True if error event, false otherwise
        """
        return code & self.ERROR_EVENT

    def poll(self, timeout):
        """Returns all file descriptors which had an event

        Args:
            timeout: Max time to wait before timing out. This is the time for which poll will block waiting for
            I/O to happen on registered FDs. If events occur before this, they will be returned without waiting for timeout.
            If this is interrupted, it will retry so no need to handle
        """
        return self.epoll.poll(timeout)

    def modify(self, fd, event):
        """Changes interest of fd to a new event

        Args:
            fd: the file descriptor
            event: new event to poll for
        """
        self.epoll.modify(fd, event)


class NonBlockingPollFactory:
    """Factory to return NonBlockingPoll (event loop) objects"""

    @staticmethod
    def getNonBlockingPoll(*params, **kwargs):
        return NonBlockingPoll(*params, **kwargs)


if __name__ == "__main__":
    # code for tests and logic to run only this module goes here
    pass
