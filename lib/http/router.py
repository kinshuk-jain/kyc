import urllib.parse as url
import re
import time
import asyncio

__version__ = "0.1"


"""Module to call specific route handlers based on requests"""

_middlewares = []
_routes = {}
_error_handler = None
# DO NOT support TRACE
_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD", "CONNECT"]
_handler_path_validator = re.compile(r"^/?(\w+-?\$?@?/?|{{\w+}}/?)+\*?$", re.ASCII)
_request_path_validator = re.compile(r"^/?(\w+-?\$?@?/?\??)+$", re.ASCII)


def add_middleware(func):
    """Add a function to be executed for all routes

    The functions are executed in the order in which they were added using this method. So
    if funcA was added before funcB, it will be executed before

    Args:
    func: function to be run as middlware
    """
    if not callable(func):
        raise ValueError("Middleware must be a function")
    _middlewares.append(func)


def _run_middlewares(request, response):
    """Internal Only. Runs all middlewares"""
    for middleware in _middlewares:
        middleware(request, response)


def add_error_handler(handler):
    """Add a generic error handler to catch all uncaught exceptions

    We can have only one generic error handler. Multiple handlers are not supported

    Args:
        handler: function to be called on error. It will be passed the exception that occurred, request and response
    """
    if not callable(handler):
        raise ValueError("error handler must be a function")
    _error_handler = handler


def add_route(method, route, handler):
    """Add a route handler

    Args:
        `method`: http verb like get, post, head, etc
        `route` - the route in string form. It can have variables within {{}} like /this/is/{{example}}/{{url}}/.
        It can also have * to match anything or * in the end like /this/is/example/* to match anything in the end.
        * is not allowed in the middle of the URL or at the beginning.
        `handler` - the function to be called for this route. The function will receive request and response
            streams as first and second arguments respectively
    """
    if not type(route) == str or route == "" or route == None:
        raise ValueError("route must be a non empty string")

    if not type(method) == str:
        raise ValueError("method must be a string")

    if not callable(handler):
        raise ValueError("route handler must be a function")

    if method.upper() not in _methods:
        raise ValueError("Invalid HTTP method")

    if not hasattr(_routes, method):
        _routes[method] = []
    if route != "/":
        route = route.strip("/")

    if route == "*" or route == "/" or _handler_path_validator.fullmatch(route):
        _routes[method].append({"path": route, "handler": handler})
    else:
        raise ValueError("Invalid route: %s" % route)


def _parse_path(request, response):
    """Internal Only. Parses and sets path

    Args: request, response streams
    """
    parsed = url.urlparse(request.path)
    # relative path
    if not _request_path_validator.fullmatch(parsed.path):
        response.send_response(400, "Invalid URL")
        return
    request.path = parsed.path
    # Parameters for last path element
    request.params = parsed.params
    # query string as a dict
    request.query = url.parse_qs(parsed.query)
    # hash value
    request.fragment = parsed.fragment
    # hostname
    request.hostname = request.headers.get("host", "") or parsed.hostname
    # port if available
    request.port = parsed.port


def _route_matcher(handler_route, request):
    """Internal Only. Checks if the routes passed to it is for the request. If the route contains {{params}} and routes match,
    the request will be passed these params in path_params as dictionary

    Args:
        handler_route: route added with handler
        request: HTTP request

    Returns:
        True if routes match
        False otherwise
    """
    req_route = request.path

    if handler_route == "*":
        return True
    elif req_route == "/":
        return handler_route == req_route
    else:
        path_params = {}
        req_route = req_route.strip("/")

        req_route_parts = req_route.split("/")
        handler_route_parts = handler_route.split("/")

        if len(handler_route_parts) != len(req_route_parts):
            return False

        for i in range(0, len(handler_route_parts)):
            if handler_route_parts[i].startswith("{{") and handler_route_parts[
                i
            ].endswith("}}"):
                param = handler_route_parts[i].strip("{}")
                path_params[param] = req_route_parts[i]
                continue
            elif handler_route_parts[i] == "*":
                return True
            elif handler_route_parts[i] != req_route_parts[i]:
                return False
        # add path_params to reqeust
        if len(path_params):
            request.path_params = path_params
        return True


def _call_route_handler(request, response):
    """Match the request path to its handler and call that function"""
    path = request.path
    # this must be upper case
    method = request.method.upper()

    if not hasattr(_routes, method):
        raise Exception("No handler for route: %s %s" % (method, path))

    route_found = False

    # this logic will call all handlers for the route. So if there are 3 handlers for a route,
    # all of them will be called
    for route in _routes[method]:
        if _route_matcher(route["path"], request):
            route_found = True
            route["handler"](request, response)

    if not route_found:
        print("No handler for route: %s %s" % (method, path))


def _handle_request(request, response):
    try:
        # NOTE: the order of calling these functions is very important
        request.start_time = time.time()
        # parse path
        _parse_path(request, response)
        # run middlewares
        _run_middlewares(request, response)
        # call route handler
        _call_route_handler(request, response)
    except Exception as e:
        if _error_handler:
            _error_handler(e, request, response)
        else:
            raise e


def on_request(request, response):
    """Runs when request is received by router.

    It executes all middlewares, parses request path and calls the right route handler
    Args: request, response streams
    """
    # TODO: if loop is running, create task and run it
    # else run the loop, create task and run it
    _handle_request(request, response)


# support cors

"""
TODO:
implement set_cookie on response
call on_request in a coroutine
Support CORS in router
"""
