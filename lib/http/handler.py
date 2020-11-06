import email.parser
import email.utils
import time
import html
import json
import datetime
import os
import gzip
import hashlib
from lib import streams
from lib import utils
from http import client
from http import HTTPStatus

EOL1 = b"\n\n"
EOL2 = b"\n\r\n"

# Max limit on length of request line
REQUESTLINE_LIMIT = 2060

# max allowed headers
MAX_HEADERS = 100

# 16KB max header length allowed
# So cookies should be kept short
# Note: this also includes user agent length
MAX_HEADER_LENGTH = 16 * 1024

# encoding on headers and request line
HEADER_ENCODING_DEFAULT = "iso-8859-1"

# encoding on body. If at any point we decide to change this to any format that has more than
# 8 bits, then we must ensure byte endianness is taken into account. One machine may be little endian
# while other one may be big endian
BODY_ENCODING_DEFAULT = "utf-8"

# max allowed body length, 100 KB
# This is used only for non binary data
MAX_BODY_LENGTH = 100 * 1024

# HTTP Reason codes
REASON_CODES = {
    100: "Continue",
    101: "Switching Protocols",
    200: "OK",
    201: "Created",
    202: "Accepted",
    203: "Non-Authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    307: "Temporary Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Time-out",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Request Entity Too Large",
    414: "Request-URI Too Large",
    415: "Unsupported Media Type",
    416: "Requested range not satisfiable",
    417: "Expectation Failed",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Time-out",
    505: "HTTP Version not supported",
}


class HTTPResponseHandler:
    """Class for handling http response. Supports HTTP/0.9, HTTP/1.0, HTTP/1.1

    It is a hard requirement that request stream must have ended before response can be sent.
    Otherwise browsers show unexpeted behaviours
    """

    def __init__(
        self,
        response_stream=streams.IOStreamFactory.getIOStream(),
        version="HTTP/1.1",
        method="GET",
        path="",
        headers=None,
    ):
        self._response_stream = response_stream
        self._response_stream.on("data", lambda x: 0)
        self._request_version = version
        self._method = method
        self._path = path
        # this is of type client.HTTPMessage if present
        self._req_headers = headers
        self._headers = []
        self._response_stream.send_response = self.send_response
        self._response_stream.send_file = self.send_file
        self._response_stream.send_header = self.send_header
        self._response_stream.redirect = self.redirect
        self._response_stream.send_stream = self.send_stream
        self._response_stream.close_connection = self.close_connection

    def _check_status_code(self, code):
        """Check validity of status code. Internal only"""
        if not code:
            raise ValueError("status code required")
        elif type(code) != int:
            raise ValueError("status code should be of type int")

    def _set_common_headers(self):
        """Internal Only. Used to set common headers for all responses"""
        self.send_header("Date", self._date_time_string())

    def send_response(self, code, message=None):
        """Send http response. Can be used to send a valid or error response of type html, text or json

        Args:
            code: Status code
            message: response body to send. Can be of type string, list, array, tuple, dict or stringified html
        """
        self._check_status_code(code)
        ctype = ""
        if hasattr(self, "_send_in_progress"):
            raise Exception("Cant send again")

        if message == None:
            ctype = "text/html;charset=utf-8"
            message = ""
        elif type(message) == dict or type(message) == list:
            ctype = "application/json"
            try:
                message = json.dumps(message, check_circular=False)
            except (SyntaxError, TypeError):
                raise ValueError("Message not a valid JSON")
        elif type(message) == str:
            ctype = "text/html;charset=utf-8"
        else:
            raise ValueError("Cannot send message of type %s" % type(message))

        try:
            reason = REASON_CODES[code]
        except KeyError:
            reason = "???"

        self._set_response_statusline(code, reason)
        # Message body is omitted for cases described in:
        #  - RFC7230: 3.3. 1xx, 204(No Content), 304(Not Modified)
        #  - RFC7231: 6.3.6. 205(Reset Content)
        body = None

        if code >= 200 and code not in (
            HTTPStatus.NO_CONTENT,
            HTTPStatus.RESET_CONTENT,
            HTTPStatus.NOT_MODIFIED,
        ):
            # HTML encode to prevent Cross Site Scripting attacks
            message = html.escape(message, quote=False)
            body = message.encode("UTF-8", "replace") + b"\r\n"
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", ctype)

        self._set_common_headers()
        self._end_headers()

        self._send_in_progress = True

        if self._method != "HEAD" and body:
            self._message_view = memoryview(b"".join(self._headers) + body)
            del self._headers
            self._response_stream._start_response(self._response_stream.client.fileno())
            self._response_stream.on("drain", self._send)
            self._send()

    def send_stream(self, code, input_stream):
        """streams a response to the client reading from another stream.

        Remember to set appropriate response headers when sending stream. Most importantly,
        `content-type` and `content-length` headers should be set\n
        Args:
            code: status code
            input_stream: readable stream to get data from. It MUST support a read method allowing
                          to read specific number of bytes from it
        """
        if hasattr(self, "_send_in_progress"):
            raise Exception("Cant send again")

        if (
            self._req_headers.get("transfer-encoding", "").lower() == "chunked"
            and self._request_version != "HTTP/1.1"
        ):
            raise Exception(
                "Found http version %s. Chunked data allowed only for HTTP/1.1"
                % self._request_version
            )

        try:
            reason = REASON_CODES[code]
        except KeyError:
            reason = "???"

        self._set_response_statusline(code, reason)
        self.send_header("Cache-Control", "no-store")
        self._set_common_headers()
        # only work on https
        self.send_header(
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains; preload",
        )
        self._end_headers()
        self._send_in_progress = True
        self._input_stream = input_stream
        self._response_stream._start_response(self._response_stream.client.fileno())
        self._response_stream.on("drain", self._stream)
        self._stream()

    def _stream(self):
        """Internal Only. Writes stream data to response stream"""
        bytes_to_write = self._response_stream.can_write()
        if bytes_to_write > 0:
            data = self._input_stream.read(bytes_to_write)
            if not data:
                self._response_stream.off("drain")
                self._response_stream.end()
                self._input_stream.close()
            else:
                self._response_stream.write(data)

    def send_file(
        self,
        code,
        path,
        content_type="application/octet-stream",
        send_etag=False,
        cache_control="no-store",
        compression="",
    ):
        """Sends a file

        Args:
            `code`: status code
            `Path`: path of file - should be absolute path,
            `content_type`: value of content type header as string. By default it is treated as octet-stream
            `send_etag`: should this file have an etag. Do not use this for files that contain data that should not be public
            `cache_control`: value of cache-control header as a string
            `compression`: type of compression on file if it is compressed. It is mandatory if file is compressed
        """
        self._check_status_code(code)

        if code < 200 or code in (
            HTTPStatus.NO_CONTENT,
            HTTPStatus.RESET_CONTENT,
            HTTPStatus.NOT_MODIFIED,
        ):
            raise ValueError("Cannot use status code %d to send file" % code)

        if self._method == "HEAD":
            raise ValueError("Cannot send file with HEAD")

        if type(path) != str:
            raise ValueError("path must be a string")

        if hasattr(self, "_send_in_progress"):
            raise Exception("Cant send again")

        if path.endswith("/"):
            self.send_response(HTTPStatus.NOT_FOUND, "File not found")

        try:
            # path should be absolute
            f = open(path, "rb")
        except OSError:
            self.send_response(HTTPStatus.NOT_FOUND, "File not found")

        try:
            fs = os.fstat(f.fileno())

            def compute_etag():
                # etag based on file descriptor, last modified time and length of file
                etag = (
                    "%d: %s: %d"
                    % (f.fileno(), self._date_time_string(fs.st_mtime), fs[6])
                ).encode()
                return hashlib.md5(etag).hexdigest()

            # Use browser cache if possible
            if self._req_headers:
                if self._req_headers.get(
                    "If-Modified-Since"
                ) and not self._req_headers.get("If-None-Match"):
                    # compare If-Modified-Since and time of last file modification
                    try:
                        ims = email.utils.parsedate_to_datetime(
                            self._req_headers.get("If-Modified-Since")
                        )
                    except (TypeError, IndexError, OverflowError, ValueError):
                        # ignore ill-formed values
                        pass
                    else:
                        if ims.tzinfo is None:
                            # obsolete format with no timezone, cf.
                            # https://tools.ietf.org/html/rfc7231#section-7.1.1.1
                            ims = ims.replace(tzinfo=datetime.timezone.utc)
                        if ims.tzinfo is datetime.timezone.utc:
                            # compare to UTC datetime of last modification
                            last_modif = datetime.datetime.fromtimestamp(
                                fs.st_mtime, datetime.timezone.utc
                            )
                            # remove microseconds, like in If-Modified-Since
                            last_modif = last_modif.replace(microsecond=0)

                            if last_modif <= ims:
                                self.send_response(HTTPStatus.NOT_MODIFIED)
                                self.end_headers()
                                f.close()
                                return

                elif self._req_headers.get("If-None-Match"):
                    inm = self._req_headers.get("If-None-Match")
                    if inm != None and inm.rstrip() != "*":
                        # we use only weak matching so remove W/
                        etag_list = map(lambda x: x.lstrip("Ww/"), inm.split(","))
                        if compute_etag() in etag_list:
                            self.send_response(HTTPStatus.NOT_MODIFIED)
                            self.end_headers()
                            f.close()
                            return

            if send_etag:
                e = compute_etag()
                self.send_header("ETag", e)

            try:
                reason = REASON_CODES[code]
            except KeyError:
                reason = "???"

            self._set_response_statusline(code, reason)
            self.send_header("Content-type", content_type)
            self.send_header("Content-Length", str(fs[6]))
            self.send_header("Last-Modified", self._date_time_string(fs.st_mtime))
            self._set_common_headers()

            # only work on https
            self.send_header(
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains; preload",
            )
            self.send_header("Cache-Control", cache_control)

            if compression:
                encodings = self._req_headers.get("accept-encoding", "")
                if compression in encodings:
                    self.send_header("Content-Encoding", compression)

            self._end_headers()

            self._send_in_progress = True

            # send file
            self._input_stream = f
            self._response_stream._start_response(self._response_stream.client.fileno())
            self._response_stream.on("drain", self._stream)
            self._stream()
        except:
            f.close()
            raise

    def redirect(self, code, location):
        """Send http redirect.

        Args:
            code: Status code. Should be valid
            location: location to redirect to. Should be a string
        """
        self._check_status_code(code)
        if code < 300 or code > 307 or code == 306:
            raise ValueError("Invalid status code %d for redirect" % code)

        if hasattr(self, "_send_in_progress"):
            raise Exception("Cant send again")

        try:
            msg = REASON_CODES[code]
        except:
            msg = "???"
        self._set_response_statusline(code, msg)
        self.send_header("Location", location)
        self._set_common_headers()
        self._end_headers()
        self._message_view = memoryview(b"".join(self._headers))
        del self._headers
        self._send_in_progress = True
        self._response_stream._start_response(self._response_stream.client.fileno())
        self._response_stream.on("drain", self._send)
        self._send()

    def _send(self):
        """Internal only. Write bytes to response stream. Cannot be used to send large responses or files or streams"""
        bytes_to_write = self._response_stream.can_write()
        if (
            bytes_to_write > 0
            and hasattr(self, "_message_view")
            and len(self._message_view)
        ):
            self._response_stream.write(self._message_view[0:bytes_to_write].tobytes())
            self._message_view = self._message_view[bytes_to_write:]
        elif hasattr(self, "_message_view") and len(self._message_view) == 0:
            # all data sent, remove listener
            self._response_stream.off("drain")
            self._response_stream.end()
            del self._message_view

    def _date_time_string(self, timestamp=None):
        """Return the current date and time formatted for a message header. Internal only

        Args:
            timestamp: a valid timestamp compatible with python time module
        """
        if timestamp is None:
            timestamp = time.time()
        return email.utils.formatdate(timestamp, usegmt=True)

    def _set_response_statusline(self, code, message=None):
        """Send the response status line only. Internal only

        Args:
            code: Status code
            message: short message to set in HTTP response status line
        """
        if self._request_version != "HTTP/0.9":
            if message == None:
                try:
                    message = REASON_CODES[code]
                except KeyError:
                    message = "???"
            self._headers.append(
                ("%s %d %s\r\n" % (self._request_version, code, message)).encode(
                    HEADER_ENCODING_DEFAULT, "strict"
                )
            )

    def send_header(self, keyword, value):
        """Set a response header

        Args:
            keyword: Header key. Should be string
            value: Value for header. Should be string
        """
        if type(keyword) != str or type(value) != str:
            raise ValueError("arguments should be of type string")

        if self._request_version != "HTTP/0.9":
            self._headers.append(
                ("%s: %s\r\n" % (keyword, value)).encode(
                    HEADER_ENCODING_DEFAULT, "strict"
                )
            )

        if keyword.lower() == "connection":
            if value.lower() == "close":
                self._close_connection = True
            elif value.lower() == "keep-alive":
                self._close_connection = False

    def _end_headers(self):
        """Send the blank line ending the headers. Internal only"""
        if self._request_version != "HTTP/0.9":
            self._headers.append(b"\r\n")

    def close_connection(self):
        """Returns whether connection with client should be closed after this request or not"""
        if hasattr(self, "_close_connection"):
            return self._close_connection
        elif self._request_version != "HTTP/0.9":
            return False
        return True

    def get_response(self):
        """returns back the underlying response stream. This method should never be needed"""
        return self._response_stream

    def end(self):
        """End the stream"""
        self._response_stream.end()

    def close(self):
        """Close the stream"""
        self._response_stream.close()


class HTTPRequestHandler:
    """Class to handle incoming http requests and parse body if possible. Supports HTTP/0.9, HTTP/1.0, HTTP/1.1"""

    _header_length = 0
    _requestline = ""

    def __init__(self, request_stream, response_stream):
        """Init

        Args:
            request_stream: The request stream for which this handler was created
        """
        self._request_stream = request_stream
        self._response_stream = response_stream
        self._request_stream.on("data", self._read_request)

    def send_error(self, *args):
        self._create_response(request_end=True, load_router=False)
        self._response_stream.send_header("Connection", "close")
        self._response_stream.send_response(*args)

    def _parse_request_line(self):
        """Internal only. Parses request line

        Returns:
            True if successful
            False otherwise
        """
        self._close_connection = True
        if len(self._requestline) > REQUESTLINE_LIMIT:
            self.send_error(
                HTTPStatus.REQUEST_URI_TOO_LONG, "URL too long (%r)" % self._requestline
            )
            return False

        # remove all trailing spaces and or newline
        self._requestline = self._requestline.rstrip("\r\n")

        # split request line on space
        requestline_elements = self._requestline.split()
        requestline_element_len = len(requestline_elements)

        if (requestline_element_len == 0) or not (2 <= requestline_element_len <= 3):
            self.send_error(
                HTTPStatus.BAD_REQUEST, "Bad request syntax (%r)" % self._requestline
            )
            return False

        elif requestline_element_len == 2:
            if requestline_elements[0] != "GET":
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Bad HTTP/0.9 request type (%r)" % requestline_elements[0],
                )
                return False

        elif requestline_element_len == 3:
            try:
                # Request line has format - Method SP Request-URI SP HTTP-Version CRLF
                # Example - POST /example HTTP/1.1
                # extract last part to get http version
                version = requestline_elements[-1]

                if not version.startswith("HTTP/"):
                    raise ValueError

                # get http version
                base_version_number = version.split("/", 1)[1]
                version_number = base_version_number.split(".")
                if len(version_number) != 2:
                    raise ValueError

                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                self.send_error(
                    HTTPStatus.BAD_REQUEST, "Bad request version (%r)" % version
                )
                return False

            if version_number >= (2, 0):
                self.send_error(
                    HTTPStatus.HTTP_VERSION_NOT_SUPPORTED,
                    "Invalid HTTP version (%s)" % base_version_number,
                )
                return False

            # version of http
            self._request_stream.http_version = version

            # HTTP method like POST, HEAD, GET, etc
            self._request_stream.method = requestline_elements[0].upper()

            # HTTP path
            self._request_stream.path = requestline_elements[1]

        self._close_connection = False
        return True

    def _parse_headers(self, header_string):
        """Internal only. Parses headers line

        Returns:
            True if successful
            False otherwise
        """
        self._close_connection = True
        if self._header_length > MAX_HEADER_LENGTH:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Got more than %d bytes when reading header line" % MAX_HEADER_LENGTH,
            )
            return False

        num_headers = header_string.count("\n")
        if num_headers >= MAX_HEADERS:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Got more than %d headers" % MAX_HEADERS,
            )
            return False

        # remove all trailing CR and LF and spaces
        header_string = header_string.rstrip(" \r\n")
        try:
            # built in python method to parse headers
            # here self._request_stream.headers is of type email.message.Message
            self._request_stream.headers = email.parser.Parser(
                _class=client.HTTPMessage
            ).parsestr(header_string)

            self._content_left = self._request_stream.headers.get("content-length")

            if self._content_left != None:
                self._content_left = int(self._content_left)

            encoding = self._request_stream.headers.get("content-encoding", "").lower()

            # do not allow multiple compression on data
            if "," in encoding:
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Multiple compression not allowed in content-encoding",
                )
                return False

            self._close_connection = False
            return True
        except:
            self.send_error(
                HTTPStatus.BAD_REQUEST,
                "Invalid headers",
            )
            return False

    def _process_headers(self):
        """Internal only. Processes headers"""
        # read request line of HTTP which is first line
        self._requestline = self._request_stream.readLine().decode(
            HEADER_ENCODING_DEFAULT
        )

        # read headers of http which start from second line
        header_string = self._request_stream.read(
            self._header_length - len(self._requestline)
        ).decode(HEADER_ENCODING_DEFAULT)

        # flag to control whether to parse request body or not depending upon whether
        # the request is valid or not
        if self._parse_request_line() and self._parse_headers(header_string):
            # Examine the headers as they are not available
            # set content-type
            self._content_type = self._request_stream.headers.get(
                "content-type", ""
            ).lower()

            # look for an Expect directive
            expect = self._request_stream.headers.get("Expect", "")
            if (
                expect.lower() == "100-continue"
                and self._request_stream.http_version >= "HTTP/1.1"
            ):
                self._response_stream.send_response(HTTPStatus.CONTINUE)
                return True

            # see if connection is to be closed
            conntype = self._request_stream.headers.get("Connection", "").lower()
            # we do not support persistent connection for http/1.0
            if conntype == "close" or self._request_stream.http_version < "HTTP/1.1":
                self._close_connection = True
            return True
        return False

    def _should_read_body(self):
        """Internal Only. Checks whether body should be read and parsed or ignored for router handler
        to take care of. If body should be ignored, it creates response

        Body if passed for GET, OPTIONS, HEAD, TRACE, CONNECT will be ignored
        Similarly if content-type is not text/* or application/json or application/x-www-form-urlencoded
        body will be ignored and must be handled by router handler.
        If transfer-encoding header is chunked, body is ignored and must be handler by router handler.

        Returns:
        A bool tuple with first part indicating whether we will buffer body to parse it later, second part
        indicating whether we only track content received and do not buffer body
        """
        if self._request_stream.method in [
            "GET",
            "OPTIONS",
            "HEAD",
            "TRACE",
            "CONNECT",
        ]:
            # we create response for these methods as body for them is ignored
            self._create_response(request_end=True)
            return False

        if (
            self._request_stream.headers.get("transfer-encoding", "").lower()
            == "chunked"
        ):
            if self._request_stream.http_version == "HTTP/1.1":
                # mark that this request body is a stream
                self._request_stream.stream_body = True
                self._create_response()
            else:
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Transfer-Encoding header not supported by %s"
                    % self._request_stream.http_version,
                )
            return False

        if not (
            self._content_type.startswith("text/")
            or self._content_type.startswith("application/json")
            or self._content_type.startswith("application/x-www-form-urlencoded")
        ):
            # mark that this request body is a stream
            self._request_stream.stream_body = True
            self._create_response()
            return False

        return True

    def _read_body(self, data_len):
        """Internal only. Reads body after headers have been received

        It sets the body as bytes of data provided it is less than MAX_BODY_LENGTH.

        Args:
            data_len: len of data read as part of body
        """
        if not self._buffer_body:
            return

        # if no body create it
        if not hasattr(self, "_body"):
            self._body_length = 0
            self._body = bytearray(min(self._content_left, MAX_BODY_LENGTH))
            self._body_view = memoryview(self._body)

        if data_len + self._body_length > MAX_BODY_LENGTH:
            self.send_error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "Request body more than %d bytes" % MAX_BODY_LENGTH,
            )
            return

        if self._content_left > 0:
            size = min(data_len, self._content_left)
            chunk = self._body_view[self._body_length : self._body_length + size]
            chunk[:] = self._request_stream.read(size)
            self._body_length += size
            self._content_left -= size
            if self._content_left <= 0:
                self._parse_body()
                self._create_response(request_end=True)
        elif self._content_left == None:
            # content length is not known so read till timeout
            # or till client closes connection. This means we read everything
            d = self._request_stream.read()
            self._body_length += len(d)
            chunk = self._body_view[self._body_length : self._body_length + len(d)]
            chunk[:] = d
        else:
            # this scenario can be only reached when client is misbehaving i.e.
            # it is sending more data than specified in content-length
            # If this happens we ignore more data and send error
            self.send_error(
                HTTPStatus.BAD_REQUEST,
                "Cannot send more than %d bytes" % self._body_length,
            )

    def _read_request(self, data):
        """Internal only. function to read requests and parse the headers

        It does not parse the body, but marks end of request based on content-length,
        HTTP method and content type
        """
        # when no headers present, read them
        # we do not buffer headers here as the assumption is that stream buffer is larger than
        # max allowed headers. This is for optimization
        if not hasattr(self._request_stream, "headers"):
            successful_headers = False
            new_headers = 0
            if EOL1 in data:
                new_headers = data.index(EOL1) + len(EOL1)
                self._header_length += new_headers
                successful_headers = self._process_headers()
            elif EOL2 in data:
                new_headers = data.index(EOL2) + len(EOL2)
                self._header_length += new_headers
                successful_headers = self._process_headers()
            else:
                self._header_length += len(data)
                if self._header_length > MAX_HEADER_LENGTH:
                    self._close_connection = True
                    self.send_error(
                        HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                        "Got more than %d bytes when reading header line"
                        % MAX_HEADER_LENGTH,
                    )

            # Evaluate headers and start reading body
            if successful_headers:
                self._buffer_body = self._should_read_body()
                # read part minus header length
                self._read_body(len(data) - new_headers)
            else:
                self.close()
        else:
            self._read_body(len(data))

    def _create_response(self, request_end=False, load_router=True):
        """function to create response stream. Internal only

        This method calls body parses and route handlers as now response can be written

        Args:
            load_router: if true, also call router
        """
        # initialize response stream
        if not hasattr(self._response_stream, "init"):
            self._response_stream.init = True
            response_handler = HTTPResponseHandler(
                response_stream=self._response_stream,
                version=self._request_stream.http_version
                if hasattr(self._request_stream, "http_version")
                else None,
                method=self._request_stream.method
                if hasattr(self._request_stream, "method")
                else None,
                path=self._request_stream.path
                if hasattr(self._request_stream, "path")
                else None,
                headers=self._request_stream.headers
                if hasattr(self._request_stream, "headers")
                else None,
            )
            # IMPORTANT: Call only after response stream is set
            # Remove data listener as we are no longer interested in this
            self._request_stream.off("data")
            # if end is set, end the stream also
            if request_end:
                self._request_stream.end()

            if load_router:
                # call route handler and pass it request, response streams
                # Req.body may or may not be present
                # TODO: load router
                # self._response_stream.send_response(200, {"a": 1})
                # detach read body handler?
                pass

    def _parse_body(self):
        """Internal only. Parses request body of type application/json; text/ and application/x-www-form-urlencoded

        The results of parsing are available to route handlers via request.body
        If cannot be parsed, request.body will be empty
        """
        # if this is called means we will no longer read more body
        del self._body_view
        del self._content_left
        del self._body_length
        del self._buffer_body

        # check request body content-encoding header.
        compression = self._request_stream.headers.get("content-encoding", "").lower()
        if compression == "gzip":
            self._body = utils.decompress(self._body, True)
        elif compression == "deflate":
            self._body = utils.decompress(self._body)

        # since body is bytearray/bytes, change it to string
        self._body = self._body.decode(BODY_ENCODING_DEFAULT)
        self._request_stream.body = {}

        if self._content_type == "" or self._content_type.startswith("text/"):
            # type is text
            self._request_stream.body = self._body
            del self._body
            return
        elif self._content_type.startswith("application/json"):
            # json body, parse it
            try:
                self._request_stream.body = json.loads(self._body)
            except:
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Request body invalid",
                )
                del self._body
                return
        elif self._content_type.startswith("application/x-www-form-urlencoded"):
            # form url encoded  body of type field1=value1&field2=value2
            def convert(val):
                # make sure user provided input is only a string
                f = str(val).split("=")
                if len(f) == 2:
                    k, v = f
                    # no need to remove special characters from k if any
                    # as we made sure everything is a string
                    # remove not allowed/invalid string chars in dictionaries
                    k = k.rstrip("\r\n ")
                    if len(k):
                        self._request_stream.body[k] = v

            map(convert, self._body.split("&"))
            del self._body
            return
        else:
            # binary data, multipart data or unsupported data type
            # do nothing
            pass

    def close_connection(self):
        """Returns whether TCP connection should be kept alive or closed after request"""
        if hasattr(self._response_stream, "init"):
            return self._close_connection or self._response_stream.close_connection()
        return self._close_connection

    def get_response(self):
        """Returns the response stream if available otherwise raises exception"""
        if hasattr(self._response_stream, "init"):
            return self._response_stream
        raise Exception("response not available")

    def client_closed_request(self):
        """Called when client closed connection

        This function is called when no more data will be received as client closed socket to not send data anymore
        """
        self._close_connection = True
        # means we were buffering body for parsing later and entire content was not read or its length
        # was not known
        if hasattr(self, "_buffer_body") and (
            self._content_left > 0 or self._content_left == None
        ):
            self._parse_body()
            self._create_response(request_end=True)
        else:
            self._request_stream.end()

    def get_request(self):
        """Return request stream associated with this handler"""
        return self._request_stream

    def close(self):
        """Perform cleanup when handler is no longer needed"""
        self._request_stream.close()
        self._response_stream.close()
        if hasattr(self, "_body"):
            del self._body
            del self._body_view


class HTTPHandlerFactory:
    """Factory to return RequestHandler objects"""

    @staticmethod
    def getRequestHandler(*params, **kwargs):
        return HTTPRequestHandler(*params, **kwargs)


if __name__ == "__main__":
    # code for tests and logic to run only this module goes here
    pass

"""
TODO:
support cookies
"""
