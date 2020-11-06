### Writing your route handler

if request data is a stream, route handler must end request when all data has been received. This will be
dependent on content-length header if present. If this route also supportes chunked requests then it needs to check transfer-encoding
header also and read accordingly. Further If `content-encoding` header is present, indicates that this data is zipped, it needs to be
unzipped as well. Note multiple compressions i.e. `content-encoding: gzip, deflate` is not allowed. Clarify this point in writing route
handler documentation. Do not overwrite req end handler and res data handler
