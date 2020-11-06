__version__ = "0.1"


class Router:
    def __init__(self):
        self.middlewares = []

    def add_middleware(self, func):
        """Add a function to be executed for all requests

        The functions are executed in the order in which they were added using this method. So
        if funcA was added before funcB, it will be executed before

        Args:
        func: function to be run as middlware
        """
        if not callable(func):
            raise ValueError("Middleware must be a function")
        self.middlewares.append(func)

    def _run_middlewares(self):
        """Internal Only. Runs all middlewares"""
        for middleware in self.middlewares:
            middleware()

    def _on_request(self):
        """Internal Only. Runs when request is received by router.

        It executes all middlewares, parses request path and calls the right route handler
        """
        self._run_middlewares()

    # support cors
    # handlers for specific routes
    # params in routes
    # allow router to be attached to sub routes
    # add a catch all route for errors
    # export router singleton
