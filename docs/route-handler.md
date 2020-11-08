### Writing your route handler

if request data is a stream, route handler must end request when all data has been received. This will be
dependent on content-length header if present. Further If `content-encoding` header is present, indicates that this data is zipped, it needs to be
unzipped as well. Note multiple compressions i.e. `content-encoding: gzip, deflate` is not allowed. Clarify this point in writing route
handler documentation. Do not overwrite req end handler and res data handler

Route handler will get two params as input - request stream and response stream

Request stream has valid body when content type is application/json, text/* or application/x-www-form-urlencoded
Otherwise it is empty. Request has method which tells HTTP verb of request, it has http_version which tells the version and it has path

response has client which is client socket and has client_address
it has methods to send responses
