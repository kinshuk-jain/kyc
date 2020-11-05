import pytest
from lib.http import server

pytestmark = pytest.mark.lib

# init_requst_async calls the super method
# no polling on fd after response has ended
# closes connection when response has ended
# closes req and res stream when response has ended and its buffers are empty otherwise doesnt end response
# can send response
# can read request
# drains response stream of whatever data that is written to underlying socket
# removes handler from req stream on end
# removes interest in all poll events when req stream has ended
# does not write empty data
# can read empty data and closes reqeust
