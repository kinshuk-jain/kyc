"""Module for utils
"""

import zlib


def get_errno_from_exception(e):
    """Gets errno from exception

    Args:
        e: Exception
    Returns:
        errno if available, None otherwise
    """
    if hasattr(e, "errno"):
        return e.errno
    elif hasattr(e, "args"):
        return e.args[0]
    else:
        return None


def decompress(data, gzip=False):
    """Decompress gzip and deflate compressions.

    Can be used to decompress a chunk or complete data. Chunks are usually missing gzip headers

    Args: bytes to be unzipped
    Returns: uncompressed bytes
    """
    if gzip:
        unzip_obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
        return unzip_obj.decompress(data)
    else:
        return zlib.decompress(data, -zlib.MAX_WBITS)


if __name__ == "__main__":
    # code for tests and logic to run only this module goes here
    pass
