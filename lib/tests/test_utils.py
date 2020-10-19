import pytest
from lib import utils
import zlib
import gzip

pytestmark = pytest.mark.utils


@pytest.fixture
def get_exception_obj():
    return object()


def test_get_errno_from_exception(get_exception_obj):
    get_exception_obj.errno = 1
    errno = utils.get_errno_from_exception(get_exception_obj)
    assert errno == 1, "correctly gets errno from exception errno"


def test_get_errno_from_exception(get_exception_obj):
    get_exception_obj.args = [1, 2, 3, 4]
    errno = utils.get_errno_from_exception(get_exception_obj)
    assert errno == 1, "correctly gets errno from exception args"


def test_get_errno_from_exception(get_exception_obj):
    errno = utils.get_errno_from_exception(get_exception_obj)
    assert errno == None, "returns none if errno, args not present"


def test_decompress_handles_inflate():
    data = b"123456789"
    compressed_data = zlib.compress(data)
    assert utils.decompress(compressed_data[2:-4]) == data


def test_decompress_handles_gzip():
    data = b"123456"
    compressed_data = gzip.compress(data)
    assert utils.decompress(compressed_data, True) == data
