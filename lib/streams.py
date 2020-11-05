"""You should never need to change this module"""

import io

# in bytes, should be more than max possible HTTP header length
# This is for optimization reasons and will break HTTP server if not followed
BUFFER_SIZE = 24 * 1024  # 24 KB

# ASCII value of Line feed
EOL = 10


class BytesIOStream:
    """Implementation of binary streams

    Use write to fill the stream and read/drain to empty it.
    These streams allow only one event listener to be attached with them. They MUST not be extended to support
    more than one event listener. Rather implement another stream class based on these
    """

    def __init__(self):
        self._buf = bytearray(b"")
        self._seek = 0
        # determines if stream is closed or not
        self._closed = False
        self._events = {
            # called when data is available on stream
            "data": None,
            # called when stream drains
            "drain": None,
            # when stream ends. It ends when no more data is to be read/written
            "end": None,
            # called when stream errors
            "error": None,
            # called when stream is aborted, happens when it is closed
            "abort": None,
            # called when stream is paused,
            "pause": None,
            # called when stream is resumed,
            "resume": None,
            # called when stream is closed after it has ended
            "close": None,
        }
        self.ended = False
        self._pause = False

    def is_empty(self):
        """Returns true if stream buffer is empty false otherwise"""
        return self._seek <= 0

    def off(self, event):
        """Remove event listener.

        Args:
            event: name of event listener to remove from this stream.  If it is data event,
                   stream will be paused also as there must be at least one consumer for stream
        """
        self._is_closed()
        if event in self._events:
            if event == "data":
                self.pause()
            self._events[event] = None

    def on(self, event, callback):
        """Attach callbacks to various stream events

        As a convenience can attach listeners on ended stream. Except for close, no other event will be triggered

        Args:
            event: the event upon which callback is triggered. Events available are -

                data:  when data is available on stream.
                end:   when stream ends means when no longer usable for writing or reading, peek and drain is still allowed,
                drain: when stream drains,
                error: when stream errors, should close the stream when it errors out
                abort: when stream is closed without ending,
                pause: when stream is paused,
                resume: when stream is resumed,
                close: when stream is closed. In case of abort, abort is called before close
            callback: method to call on event
        """
        self._is_ended()
        # if even not present in events list
        if event not in self._events:
            raise ValueError("{0} does not a valid stream event".format(event))

        # check if callback is callable - can be a function or a class
        if not callable(callback):
            raise ValueError("Callback passed is not callable")

        self._events[event] = callback
        if event == "data" and self._pause and self._seek != 0:
            self.resume()
            self._events[event](self.read())

    def pause(self):
        if not self._pause:
            self._is_ended()
            self._pause = True
            if self._events["pause"]:
                self._events["pause"]()

    def resume(self):
        if self._pause:
            self._is_ended()
            self._pause = False
            if self._events["resume"]:
                self._events["resume"]()

    def _error(self, err, close_on_error=False):
        """Errors out the stream

        if an error handler is given calls it, otherwise raises an exception

        Args:
            msg: message to raise exception with
            close_on_error: should the stream be closed on error, only used when no event handler is registered
        """
        if self._events["error"]:
            self._events["error"](err)  # pylint: disable=not-callable
        else:
            if close_on_error:
                self.close()
            raise err

    def _is_closed(self):
        """Used to raise exception when any operation is done on a closed stream"""
        if self._closed:
            self._error(
                Exception("Operation now allowed. Stream already finished"), True
            )

    def _is_ended(self):
        """Used to raise exception when any operation is done on an ended stream"""
        if self.ended:
            self._error(
                Exception("Operation now allowed. Stream already finished"), True
            )

    def end(self):
        """End the stream for reading, writing.

        Should be called when finished writing to writable stream or finished reading
        from a readable stream. Drain and peek can still be done

        can be called again on an already ended stream as a convenience
        """
        self._is_closed()
        if not self.ended:
            self.ended = True

            # stream ended callback
            if self._events["end"]:
                self._events["end"]()  # pylint: disable=not-callable

    def close(self):
        """closes the stream

        can be called again on an already closed stream as a convenience
        """
        # cannot close a closed stream
        if not self._closed:
            ended = self.ended
            self._seek = 0
            del self._buf
            self._closed = True
            self.ended = True
            try:
                if self._events["close"] and ended:
                    self._events["close"]()  # pylint: disable=not-callable
                elif self._events["abort"] and not ended:
                    self._events["abort"]()  # pylint: disable=not-callable
            finally:
                del self._events

    def can_write(self):
        """tells how much space in stream buffer

        Returns:
            space in stream buffer,
            0 if no space or no data listener
            -1 if stream is closed or ended or paused
        """
        if self.ended or self._closed or self._pause:
            return -1
        # can write only when there is space in buffer and there is a data handler
        if self._seek < BUFFER_SIZE and self._events["data"] != None:
            return BUFFER_SIZE - self._seek
        return 0

    def write(self, data):
        """Write to stream.

        Args:
            data: data to write to stream. Should be of type bytes or bytesarray
        Returns:
            number of bytes written
        """
        self._is_ended()
        if not isinstance(data, (bytearray, bytes)):
            self._error(ValueError("Cannot write type %s to byte stream" % type(data)))

        elif len(data) == 0:
            return 0

        if self._seek < BUFFER_SIZE and self.can_write() > 0:
            bytes_to_write = min(len(data), BUFFER_SIZE - self._seek)

            if bytes_to_write > 0:
                data_view = memoryview(data)
                write_data = data_view[:bytes_to_write].tobytes()
                self._buf += write_data

                # update seek
                self._seek += bytes_to_write

                # data written to stream callback
                if self._events["data"]:
                    self._events["data"](write_data)  # pylint: disable=not-callable
            return bytes_to_write
        else:
            return 0

    def peek(self, size=BUFFER_SIZE):
        """peeks into the stream

        Args:
            size: size to peek
        Returns:
            data peeked
        """
        self._is_closed()
        if size <= 0:
            return b""
        peek_size = min(size, self._seek)
        with memoryview(self._buf) as view:
            return bytes(view[:peek_size])

    def drain(self, size=BUFFER_SIZE):
        """drain size from stream

        Args:
            size: size to drain
        """
        self._is_closed()
        if size <= 0:
            return
        length = min(size, self._seek)
        self._buf = self._buf[length : self._seek]
        self._seek -= length

        # stream drain callback
        try:
            if self._events["drain"]:
                self._events["drain"]()  # pylint: disable=not-callable
        finally:
            # if ended stream is completely drained, close it
            if self._seek <= 0 and self.ended:
                self.close()

    def read(self, size=BUFFER_SIZE):
        """Reads from stream and empties it

        Args:
            size: size to read
        Returns:
            data read
        """
        self._is_ended()
        if size <= 0:
            return b""
        data = self.peek(size)
        self.drain(size)
        return data

    def readLine(self, size=BUFFER_SIZE):
        """reads one line till b'\n' is reached

        This means it will also drain the stream if line is read

        Args:
            size: max bytes to read while checking for new line
        Returns:
            bytes read till newline including newline or empty byte otherwise
        """
        self._is_ended()
        if size <= 0:
            return b""
        read_end = min(size, self._seek)
        b = 0
        data = b""
        while b < read_end:
            if self._buf[b] == EOL:
                data = self.read(b + 1)
                break
            b += 1
        return data


class IOStreamFactory:
    """Factory to return BytesIOStream objects which is a stream of bytes or bytearray"""

    @staticmethod
    def getIOStream(*params, **kwargs):
        return BytesIOStream(*params, **kwargs)


if __name__ == "__main__":
    # code for tests and logic to run only this module goes here
    pass
