import email.parser
import json
from lib import streams
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


class HTTPResponseHandler:
    def __init__(self):
        # TODO: attach send methods to response stream
        self._response_stream = streams.IOStreamFactory.getIOStream()

    def send_error(self, *args):
        # TODO: send error response
        # TODO: check if all response is written
        self._response_stream.end()

    def send(self):
        pass

    def create_response(self):
        pass

    def get_response(self):
        return self._response_stream

    def end(self):
        self._response_stream.end()

    def close(self):
        self._response_stream.close()


class HTTPRequestHandler:
    """
    TODO: HTTP 2.0 not supported for now
    TODO: implement timeout
    """

    _header_length = 0
    _requestline = ""

    def __init__(self, request_stream=streams.IOStreamFactory.getIOStream()):
        """Init

        Args:
            request_stream: The request stream for which this handler was created
        """
        self._request_stream = request_stream
        self._request_stream.on("data", self._read_request)

    def send_error(self, *args):
        self._create_response(load_router=False)
        self._response_handler.send_error(*args)

    def _parse_request_line(self):
        """Internal only. Parses request line

        Returns:
            True if successful
            False otherwise
        """
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
            self._close_connection = True
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
        return True

    def _parse_headers(self, header_string):
        """Internal only. Parses headers line

        Returns:
            True if successful
            False otherwise
        """
        if len(header_string) > MAX_HEADER_LENGTH:
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
            # Examine the headers and look for an Expect directive
            expect = self._request_stream.headers.get("Expect", "")
            if (
                expect.lower() == "100-continue"
                and self._request_stream.http_version >= "HTTP/1.1"
            ):
                self._response_handler.send(HTTPStatus.CONTINUE)
                self._close_connection = True
                return True

            conntype = self._request_stream.headers.get("Connection", "").lower()
            if conntype == "close":
                self._close_connection = True
                return True

            elif self._request_stream.http_version < "HTTP/1.1":
                self._close_connection = True
                return True

            self._close_connection = False
            return True
        return False

    def close_connection(self):
        """Returns whether TCP connection should be kept alive or closed after request"""
        return self._close_connection

    def client_closed_request(self):
        """Called when client closed connection

        Parses body if handler was waiting for more data and if content length
        header was passed.
        """
        # No more data will be received
        self._close_connection = True
        if hasattr(self, "_content_left"):
            # parse body if content left, create response
            if self._content_left > 0:
                self._parse_body()
                self._create_response()
            elif self._content_left == None:
                # if content left is none pause request as response was already created
                self._request_stream.pause()

    def _read_body(self, data_len):
        """Internal only. Reads body after headers have been received

        It sets the body as bytes of data provided it is less than MAX_BODY_LENGTH.
        Body if passed for GET, OPTIONS, HEAD, TRACE, CONNECT will be ignored
        Similarly if content-type is not text/* or application/json or application/x-www-form-urlencoded
        body will be ignored

        Args:
            data_len: len of data read as part of body
        """
        if self._request_stream.method in [
            "GET",
            "OPTIONS",
            "HEAD",
            "TRACE",
            "CONNECT",
        ]:
            # we create response for these methods as body for them is ignored
            self._create_response()
            return

        if not (
            self._content_type.startswith("text/")
            or self._content_type.startswith("application/json")
            or self._content_type.startswith("application/x-www-form-urlencoded")
        ):
            # We do not read data but just check if entire content has been read or not
            # if yes, we close request
            if self._content_left > 0:
                self._content_left -= min(data_len, self._content_left)
                if self._content_left <= 0:
                    self._request_stream.pause()
            if not hasattr(self, "_response_handler"):
                # deregister data event handler
                self._request_stream.off("data")
                self._create_response()
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
                self._create_response()
        elif self._content_left == None:
            # content length is not known so read till timeout
            # or till client closes connection. This means we read everything
            d = self._request_stream.read()
            self._body_length += len(d)
            chunk = self._body_view[self._body_length : self._body_length + len(d)]
            chunk[:] = d
            # since we do not know when will this request end, we create a response
            # hoping handler might be able to understand this
            self._create_response()
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
        if not hasattr(self._request_stream, "headers"):
            successful_headers = False
            if EOL1 in data:
                self._header_length += data.index(EOL1) + len(EOL1)
                successful_headers = self._process_headers()
            elif EOL2 in data:
                self._header_length += data.index(EOL2) + len(EOL2)
                successful_headers = self._process_headers()
            else:
                self._header_length += len(data)

            # Evaluate headers and start reading body
            if successful_headers:
                self._content_left = self._request_stream.headers.get("content-length")
                self._content_type = (
                    self._request_stream.headers.get("content-type") or ""
                ).lower()

                try:
                    if self._content_left != None:
                        self._content_left = int(self._content_left)
                except:
                    self.send_error(
                        HTTPStatus.BAD_REQUEST,
                        "Invalid Content-Length header",
                    )
                self._read_body(len(data))
            else:
                self.close()
        else:
            self._read_body(len(data))

    def get_response(self):
        """Returns the response stream if available otherwise raises exception"""
        if hasattr(self, "_response_handler"):
            return self._response_handler.get_response()
        raise Exception("response not available")

    def get_request(self):
        return self._request_stream

    def _parse_body(self):
        # if this is called means we will no longer read more body
        del self._body_view
        del self._content_left
        del self._body_length

        # since body is bytearray, change it to string
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

    def _create_response(self, load_router=True):
        """function to create response stream

        This method calls body parses and route handlers as now response can be written

        Args:
            load_router: if true, also call router
        """
        # create response stream
        if not hasattr(self, "_response_handler"):
            self._response_handler = HTTPResponseHandler()
            self._request_stream.pause()
            if load_router:
                # call route handler and pass it request, response streams
                # TODO: load router
                pass

    def close(self):
        """Perform cleanup when handler is no longer needed"""
        self._request_stream.close()
        if hasattr(self, "_body"):
            del self._body
            del self._body_view
        if hasattr(self, "_response_handler"):
            self._response_handler.close()


class HTTPHandlerFactory:
    """Factory to return RequestHandler objects"""

    @staticmethod
    def getRequestHandler(*params, **kwargs):
        return HTTPRequestHandler(*params, **kwargs)


if __name__ == "__main__":
    # code for tests and logic to run only this module goes here
    pass

"""
Support transfer encoding header

start adding response data to response stream

add a router and call the right route handler in coroutine with req and res streams

when response is ended mark the stream as ended

"""
