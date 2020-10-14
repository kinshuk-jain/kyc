import zlib


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
