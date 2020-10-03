"""Main module for the program to start
"""
import sys
from lib.http.server import HTTPServer


HOST, PORT = "", 3000

REQUEST_QUEUE_SIZE = 50

# value in seconds
CLIENT_CONNECTION_TIMEOUT = 30

if __name__ == "__main__":
    # if python version is less than 3.7, raise exception
    if not (sys.version_info[0] >= 3 and sys.version_info[1] >= 7):
        raise Exception("Python version less than 3.7 not supported")

    print("Attempting to start server ...")
    http_server = HTTPServer(HOST, PORT, REQUEST_QUEUE_SIZE, CLIENT_CONNECTION_TIMEOUT)
    http_server.serve()
