import pytest
from unittest.mock import Mock
from lib import streams

pytestmark = pytest.mark.lib


@pytest.fixture
def get_io_stream():
    return streams.IOStreamFactory.getIOStream()


@pytest.fixture
def fill_stream_buffer():
    def _fill(stream, data=b"123456", data_event_callback=lambda x: x):
        streams.BUFFER_SIZE = len(data)
        stream.on("data", data_event_callback)
        return stream.write(data)

    return _fill


def test_iostream_factory(get_io_stream):
    assert isinstance(
        get_io_stream, streams.BytesIOStream
    ), "IOStream factory returns BytesIOStream objects"


def test_bytesiostream_write(get_io_stream, fill_stream_buffer):
    data = b"123456"
    result = fill_stream_buffer(get_io_stream, data)
    assert get_io_stream.read() == data
    assert result == len(data)
    assert get_io_stream.write(b"") == 0


def test_bytesiostream_write_into_available_space(get_io_stream):
    data = b"123456"
    streams.BUFFER_SIZE = len(data) - 2
    get_io_stream.on("data", lambda x: x)
    result = get_io_stream.write(data)
    assert result == streams.BUFFER_SIZE
    result = get_io_stream.write(data)
    assert result == 0


def test_bytesiostream_write_on_ended_stream(get_io_stream, fill_stream_buffer):
    get_io_stream.end()
    with pytest.raises(Exception):
        fill_stream_buffer(get_io_stream)


def test_bytesiostream_write_on_paused_stream(get_io_stream, fill_stream_buffer):
    get_io_stream.pause()
    result = fill_stream_buffer(get_io_stream)
    assert result == 0


def test_bytesostream_write_for_wrong_data_type(get_io_stream):
    data = "123456"
    get_io_stream.on("data", lambda x: x)
    with pytest.raises(ValueError) as e:
        result = get_io_stream.write(data)
        assert (
            get_io_stream.read() == data
        ), "raises value error when wrong data type passed to stream write"


def test_bytesostream_data_event_triggered_on_data(get_io_stream, fill_stream_buffer):
    mock_func = Mock()
    fill_stream_buffer(get_io_stream, data_event_callback=mock_func)
    assert mock_func.called == True, "calls data event handler"


def test_bytesostream_peek_returns_data(get_io_stream, fill_stream_buffer):
    data = b"123456"
    fill_stream_buffer(get_io_stream, data)
    assert get_io_stream.peek() == data, "returns peeked data"


def test_bytesostream_peek_does_not_drain(get_io_stream, fill_stream_buffer):
    data = b"123456"
    fill_stream_buffer(get_io_stream, data)
    get_io_stream.peek()
    assert get_io_stream.peek() == data, "does not drain buffer on peeking"


def test_bytesostream_peek_returns_data_type_bytes(get_io_stream, fill_stream_buffer):
    data = b"123456"
    fill_stream_buffer(get_io_stream, data)
    assert type(get_io_stream.peek()) == bytes, "peek returns bytes data"


def test_bytesostream_peek_within_buffer_bounds(get_io_stream):
    data = b"123456"
    streams.BUFFER_SIZE = len(data) - 2
    get_io_stream.on("data", lambda x: x)
    get_io_stream.write(b"123456")
    assert get_io_stream.peek() == data[:-2], "does not peek outside buffer bounds"


def test_bytesostream_peek_returns_data_of_size(get_io_stream):
    data = b"123456"
    streams.BUFFER_SIZE = len(data) + 2
    get_io_stream.on("data", lambda x: x)
    get_io_stream.write(b"123456")
    assert get_io_stream.peek(2) == b"12", "when size is given, peeks only size"
    assert get_io_stream.peek(0) == b"", "when size is 0, returns empty byte string"
    assert (
        get_io_stream.peek(-1) == b""
    ), "when size is negative, returns empty byte string"
    assert (
        get_io_stream.peek(streams.BUFFER_SIZE + 5) == data
    ), "does not peek after buffer size"


def test_bytesostream_peek_allowed_on_ended_stream(get_io_stream, fill_stream_buffer):
    data = b"123456"
    fill_stream_buffer(get_io_stream, data)
    get_io_stream.end()
    assert get_io_stream.peek() == data, "returns data"


def test_bytesostream_peek_not_allowed_on_closed_stream(
    get_io_stream, fill_stream_buffer
):
    fill_stream_buffer(get_io_stream)
    get_io_stream.close()
    with pytest.raises(Exception):
        get_io_stream.peek()


def test_bytesiostream_read(get_io_stream, fill_stream_buffer):
    data = b"123456"
    fill_stream_buffer(get_io_stream, data)
    assert get_io_stream.read() == data, "reads data"


def test_bytesiostream_read_drains_buffer(get_io_stream, fill_stream_buffer):
    data = b"123456"
    fill_stream_buffer(get_io_stream, data)
    get_io_stream.read(2)
    assert get_io_stream.read(2) == b"34", "drains data on read"


def test_bytesiostream_read_calls_drain_event(get_io_stream, fill_stream_buffer):
    data = b"123456"
    fill_stream_buffer(get_io_stream, data)
    mock_func = Mock()
    get_io_stream.on("drain", mock_func)
    get_io_stream.read(2)
    assert mock_func.called == True, "triggers drain event on read"


def test_bytesiostream_read_of_size(get_io_stream, fill_stream_buffer):
    data = b"123456"
    fill_stream_buffer(get_io_stream, data)
    assert get_io_stream.read(-1) == b"", "returns empty byte string on negative size"
    assert get_io_stream.read(0) == b"", "returns empty byte string on zero data"
    assert get_io_stream.read(2) == b"12", "reads only given bytes"
    assert get_io_stream.read(1000) == b"3456", "Does not read beyong buffer size"


def test_bytesiostream_read_no_read_on_ended_stream(get_io_stream, fill_stream_buffer):
    data = b"123456"
    fill_stream_buffer(get_io_stream, data)
    get_io_stream.end()
    with pytest.raises(Exception):
        assert get_io_stream.read() == data, "returns exception"


def test_bytesiostream_readLine_returns_line(get_io_stream, fill_stream_buffer):
    data = b"123456\nabcde"
    fill_stream_buffer(get_io_stream, data)
    assert get_io_stream.readLine() == b"123456\n", "reads data one line at a time"


def test_bytesiostream_readLine_drains_buffer(get_io_stream, fill_stream_buffer):
    data = b"123456\nabcde\n"
    fill_stream_buffer(get_io_stream, data)
    get_io_stream.readLine()
    assert get_io_stream.readLine() == b"abcde\n", "drains buffer on read line"


def test_bytesiostream_readLine_triggers_drain_event(get_io_stream, fill_stream_buffer):
    data = b"123456\nabcde"
    fill_stream_buffer(get_io_stream, data)
    mock_func = Mock()
    get_io_stream.on("drain", mock_func)
    get_io_stream.readLine()
    assert mock_func.called == True, "Calls drain event on read line"


def test_bytesiostream_readLine_returns_all_data(get_io_stream, fill_stream_buffer):
    data = b"123456abcde"
    fill_stream_buffer(get_io_stream, data)
    assert get_io_stream.readLine() == b"", "reads no data when it has no newline"


def test_bytesiostream_readLine_of_size(get_io_stream, fill_stream_buffer):
    data = b"123456\nabcde"
    fill_stream_buffer(get_io_stream, data)
    assert get_io_stream.readLine(-1) == b""
    assert get_io_stream.readLine(0) == b""
    assert (
        get_io_stream.readLine(2) == b""
    ), "Returns empty string when no new line found till size"
    assert get_io_stream.readLine(10) == b"123456\n"


def test_bytesiostream_readLine_no_read_on_ended_stream(
    get_io_stream, fill_stream_buffer
):
    data = b"123456"
    fill_stream_buffer(get_io_stream, data)
    get_io_stream.end()
    with pytest.raises(Exception):
        assert get_io_stream.readLine() == data, "returns exception"


def test_bytesiostream_drain_removes_data(get_io_stream, fill_stream_buffer):
    data = b"123456"
    fill_stream_buffer(get_io_stream, data)
    get_io_stream.drain()
    assert get_io_stream.read() == b"", "drains all data"


def test_bytesiostream_drain_removes_data_of_size(get_io_stream, fill_stream_buffer):
    data = b"123456"
    fill_stream_buffer(get_io_stream, data)
    mock_func = Mock()
    get_io_stream.on("drain", mock_func)
    get_io_stream.drain(-1)
    assert mock_func.called == False
    get_io_stream.drain(0)
    assert mock_func.called == False
    get_io_stream.drain(2)
    get_io_stream.drain(2)
    get_io_stream.drain(2)
    assert mock_func.call_count == 3


def test_bytesiostream_drain_triggers_event(get_io_stream, fill_stream_buffer):
    data = b"123456"
    fill_stream_buffer(get_io_stream, data)
    mock_func = Mock()
    get_io_stream.on("drain", mock_func)
    get_io_stream.drain()
    assert mock_func.called == True, "triggers drain event on drain"


def test_bytesiostream_drain_works_on_ended_stream(get_io_stream, fill_stream_buffer):
    data = b"123456"
    fill_stream_buffer(get_io_stream, data)
    get_io_stream.end()
    get_io_stream.drain(2)
    assert get_io_stream.peek() == b"3456", "drains data on ended stream"


def test_bytesiostream_drain_fails_on_closed_stream(get_io_stream, fill_stream_buffer):
    fill_stream_buffer(get_io_stream)
    get_io_stream.close()
    with pytest.raises(Exception):
        get_io_stream.drain()


def test_bytesiostream_drain_closes_completely_drained_stream_when_ended(
    get_io_stream, fill_stream_buffer
):
    fill_stream_buffer(get_io_stream)
    get_io_stream.end()
    get_io_stream.drain()
    with pytest.raises(Exception):
        get_io_stream.peek()


def test_bytesiostream_can_write_returns_correct_value(
    get_io_stream, fill_stream_buffer
):
    fill_stream_buffer(get_io_stream)
    assert get_io_stream.can_write() == 0

    get_io_stream.drain()
    assert get_io_stream.can_write() == streams.BUFFER_SIZE

    fill_stream_buffer(get_io_stream, b"1")
    assert get_io_stream.can_write() == streams.BUFFER_SIZE - 1

    get_io_stream.pause()
    assert get_io_stream.can_write() == -1

    get_io_stream.resume()
    get_io_stream.end()
    assert get_io_stream.can_write() == -1

    get_io_stream.ended = False
    get_io_stream.close()
    assert get_io_stream.can_write() == -1


def test_bytesiostream_pause_fires_event(get_io_stream):
    mock_func = Mock()
    get_io_stream.on("pause", mock_func)
    get_io_stream.pause()
    assert mock_func.called == True
    assert get_io_stream._pause == True


def test_bytesiostream_pause_does_not_fire_event_on_paused_stream(get_io_stream):
    mock_func = Mock()
    get_io_stream.pause()
    get_io_stream.on("pause", mock_func)
    get_io_stream.pause()
    assert mock_func.called == False


def test_bytesiostream_pause_fails_on_ended_stream(get_io_stream):
    get_io_stream.end()
    with pytest.raises(Exception):
        get_io_stream.pause()


def test_bytesiostream_resume_fires_event(get_io_stream):
    mock_func = Mock()
    get_io_stream.on("resume", mock_func)
    get_io_stream.pause()
    get_io_stream.resume()
    assert mock_func.called == True
    assert get_io_stream._pause == False


def test_bytesiostream_resume_does_not_fire_event_on_unpaused_stream(get_io_stream):
    mock_func = Mock()
    get_io_stream.on("resume", mock_func)
    get_io_stream.resume()
    assert mock_func.called == False


def test_bytesiostream_resume_fails_on_ended_stream(get_io_stream):
    get_io_stream.pause()
    get_io_stream.end()
    with pytest.raises(Exception):
        get_io_stream.resume()


def test_bytesiostream_end_stream_does_not_close(get_io_stream):
    get_io_stream.end()
    assert get_io_stream.ended == True
    assert get_io_stream.peek() == b""


def test_bytesiostream_end_stream_triggers_event(get_io_stream):
    mock_func = Mock()
    get_io_stream.on("end", mock_func)
    get_io_stream.end()
    assert mock_func.called == True
    # event not called again on ended stream
    get_io_stream.end()
    assert mock_func.call_count == 1


def test_bytesiostream_end_allows_multiple_ends(get_io_stream):
    get_io_stream.end()
    get_io_stream.end()
    get_io_stream.end()
    get_io_stream.end()
    assert get_io_stream.ended == True


def test_bytesiostream_end_cannot_end_closed_stream(get_io_stream):
    get_io_stream.close()
    with pytest.raises(Exception):
        get_io_stream.end()


def test_bytesiostream_close_stream_ends(get_io_stream):
    get_io_stream.close()
    assert get_io_stream.ended == True


def test_bytesiostream_close_stream_triggers_event(get_io_stream):
    mock_func = Mock()
    get_io_stream.on("close", mock_func)
    get_io_stream.end()
    get_io_stream.close()
    assert mock_func.called == True


def test_bytesiostream_close_stream_triggers_abort_event_if_not_ended(get_io_stream):
    mock_func = Mock()
    get_io_stream.on("abort", mock_func)
    get_io_stream.close()
    assert mock_func.called == True


def test_bytesiostream_close_allows_multiple_close(get_io_stream):
    get_io_stream.close()
    get_io_stream.close()
    get_io_stream.close()
    get_io_stream.close()


def test_bytesiostream_close_removes_event_listeners(get_io_stream):
    mock_func = Mock()
    get_io_stream.on("data", mock_func)
    get_io_stream.close()
    # implementation dependent test, somehow fix it?
    assert hasattr(get_io_stream, "_events") == False


def test_bytesiostream_off_removes_listener(get_io_stream, fill_stream_buffer):
    mock_func = Mock()
    get_io_stream.on("data", mock_func)
    get_io_stream.off("data")
    fill_stream_buffer(get_io_stream)
    assert mock_func.called == False


def test_bytesiostream_off_raises_exception_when_called_on_closed_stream(get_io_stream):
    mock_func = Mock()
    get_io_stream.on("data", mock_func)
    get_io_stream.close()
    with pytest.raises(Exception):
        get_io_stream.off("data")


def test_off_works_when_called_on_ended_stream(
    get_io_stream,
):
    get_io_stream.on("drain", lambda x: x)
    get_io_stream.end()
    get_io_stream.off("drain")


def test_off_works_when_removing_invalid_listener(get_io_stream):
    get_io_stream.off("blah")


def test_bytesiostream_off_pauses_stream_only_when_data_listener_removed(get_io_stream):
    get_io_stream.on("data", lambda x: x)
    get_io_stream.off("data")
    assert get_io_stream.can_write() == -1
    get_io_stream.resume()
    get_io_stream.on("data", lambda x: x)
    get_io_stream.on("pause", lambda x: x)
    get_io_stream.on("drain", lambda x: x)
    get_io_stream.on("resume", lambda x: x)
    get_io_stream.on("abort", lambda x: x)
    get_io_stream.on("close", lambda x: x)
    get_io_stream.on("error", lambda x: x)
    get_io_stream.on("end", lambda x: x)
    get_io_stream.off("pause")
    get_io_stream.off("drain")
    get_io_stream.off("resume")
    get_io_stream.off("abort")
    get_io_stream.off("close")
    get_io_stream.off("error")
    get_io_stream.off("end")
    assert get_io_stream.can_write() > 0


def test_on_does_not_attach_listener_on_ended_stream(get_io_stream):
    get_io_stream.end()
    with pytest.raises(Exception):
        get_io_stream.on("error", lambda x: x)


def test_on_does_not_attach_listener_on_closed_stream(get_io_stream):
    get_io_stream.close()
    with pytest.raises(Exception):
        get_io_stream.on("error", lambda x: x)


def test_on_throws_error_on_invalid_event_or_callback(get_io_stream):
    with pytest.raises(ValueError):
        get_io_stream.on("blah", lambda x: x)

    with pytest.raises(ValueError):
        get_io_stream.on("blah", "123")


def test_on_attaches_listerner(get_io_stream):
    mock_func = Mock()
    get_io_stream.on("end", mock_func)
    get_io_stream.end()
    assert mock_func.called == True


def test_on_triggers_data_event_when_attached_on_paused_stream_with_data(get_io_stream):
    mock_func_data = Mock(return_value=None)
    mock_func_resume = Mock(return_value=None)
    get_io_stream.on("data", lambda x: x)
    get_io_stream.on("resume", mock_func_resume)
    get_io_stream.write(b"123456")
    get_io_stream.off("data")
    get_io_stream.on("data", mock_func_data)
    assert mock_func_resume.called == True
    assert mock_func_data.called == True
    mock_func_data.assert_called_once_with(b"123456")
