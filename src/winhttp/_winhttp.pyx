
# cython: language_level=3
# distutils: libraries = winhttp

#region Error Handling

ERROR_MAP = {
    ERROR_WINHTTP_INCORRECT_HANDLE_TYPE: 'The type of handle supplied is incorrect for this operation.',
    ERROR_WINHTTP_INTERNAL_ERROR: 'An internal error has occurred.',
    ERROR_WINHTTP_INVALID_URL: 'The URL is invalid.',
    ERROR_WINHTTP_OPERATION_CANCELLED: 'The operation was canceled.',
    ERROR_WINHTTP_UNRECOGNIZED_SCHEME: 'The URL specified a scheme other than "http:" or "https:".',
    ERROR_WINHTTP_CANNOT_CONNECT: 'Connection to the server failed.',
    ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED: 'The secure HTTP server requires a client certificate.',
    ERROR_WINHTTP_CONNECTION_ERROR: 'The connection with the server has been reset or terminated, or an incompatible SSL protocol was encountered.',
    ERROR_WINHTTP_INCORRECT_HANDLE_STATE: 'The requested operation cannot be carried out because the handle supplied is not in the correct state.',
    ERROR_WINHTTP_LOGIN_FAILURE: 'The login attempt failed.',
    ERROR_WINHTTP_NAME_NOT_RESOLVED: 'The server name cannot be resolved.',
    ERROR_WINHTTP_RESPONSE_DRAIN_OVERFLOW: 'An incoming response exceeds an internal WinHTTP size limit.',
    ERROR_WINHTTP_SECURE_FAILURE: 'One or more errors were found in the Secure Sockets Layer (SSL) certificate sent by the server.',
    ERROR_WINHTTP_SHUTDOWN: 'The WinHTTP function support is shut down or unloaded.',
    ERROR_WINHTTP_TIMEOUT: 'The request timed out.',
    ERROR_WINHTTP_RESEND_REQUEST: 'The request must be sent again due to a redirect or authentication challenge.',
    ERROR_INVALID_PARAMETER: 'A parameter is invalid',
    ERROR_NOT_ENOUGH_MEMORY: 'Not enough memory was available to complete the requested operation.',
}

def handle_HINTERNET(DWORD_PTR p, DWORD cb):
    if cb == sizeof(HINTERNET):
        return (<const DWORD_PTR*>p)[0]

def handle_WINHTTP_ASYNC_RESULT(DWORD_PTR p, DWORD cb):
    if cb != sizeof(WINHTTP_ASYNC_RESULT):
        return None
    rp = <const WINHTTP_ASYNC_RESULT*>p
    source, error = rp.dwResult, rp.dwError
    source_msg = {
        API_RECEIVE_RESPONSE: 'receive_response',
        API_QUERY_DATA_AVAILABLE: 'query_data_available',
        API_READ_DATA: 'read_data',
        API_WRITE_DATA: 'write_data',
        API_SEND_REQUEST: 'send_request',
    }.get(source, 'unknown')
    error_msg = ERROR_MAP.get(error) or 'error 0x{:08X}'.format(error)
    return error, source_msg, error_msg

STATUS_MAP = {
    WINHTTP_CALLBACK_STATUS_CLOSING_CONNECTION: ('closing_connection', None),
    WINHTTP_CALLBACK_STATUS_CONNECTED_TO_SERVER: ('connected_to_server', str),
    WINHTTP_CALLBACK_STATUS_CONNECTING_TO_SERVER: ('connecting_to_server', str),
    WINHTTP_CALLBACK_STATUS_CONNECTION_CLOSED: ('connection_closed', None),
    WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE: ('data_available', int),
    WINHTTP_CALLBACK_STATUS_HANDLE_CREATED: ('handle_created', handle_HINTERNET),
    WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING: ('handle_closing', handle_HINTERNET),
    WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE: ('headers_available', None),
    WINHTTP_CALLBACK_STATUS_INTERMEDIATE_RESPONSE: ('intermediate_response', int),
    WINHTTP_CALLBACK_STATUS_NAME_RESOLVED: ('name_resolved', str),
    WINHTTP_CALLBACK_STATUS_READ_COMPLETE: ('read_complete', bytes),
    WINHTTP_CALLBACK_STATUS_RECEIVING_RESPONSE: ('receiving_response', None),
    WINHTTP_CALLBACK_STATUS_REDIRECT: ('redirect', str),
    WINHTTP_CALLBACK_STATUS_REQUEST_ERROR: ('request_error', handle_WINHTTP_ASYNC_RESULT),
    WINHTTP_CALLBACK_STATUS_REQUEST_SENT: ('request_sent', int),
    WINHTTP_CALLBACK_STATUS_RESOLVING_NAME: ('resolving_name', str),
    WINHTTP_CALLBACK_STATUS_RESPONSE_RECEIVED: ('response_received', int),
    WINHTTP_CALLBACK_STATUS_SECURE_FAILURE: ('secure_failure', int),
    WINHTTP_CALLBACK_STATUS_SENDING_REQUEST: ('sending_request', None),
    WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE: ('sendrequest_complete', None),
    WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE: ('write_complete', int),
    WINHTTP_CALLBACK_STATUS_GETPROXYFORURL_COMPLETE: ('getproxyforurl_complete', None),
    WINHTTP_CALLBACK_STATUS_CLOSE_COMPLETE: ('close_complete', None),
    WINHTTP_CALLBACK_STATUS_SHUTDOWN_COMPLETE: ('shutdown_complete', None),
}

cdef int raise_error(DWORD err=0) nogil except? -1:
    if err == 0:
        err = GetLastError()
    with gil:
        msg = ERROR_MAP.get(err)
        if msg:
            raise OSError(err, msg)
        raise OSError(err, "Unknown error: {0} (0x{0:08X})".format(err))

cdef HINTERNET check_handle(HINTERNET r) except? NULL:
    if not r:
        raise_error()
    return r

cdef BOOL check_bool(BOOL r) except? 0:
    if not r:
        raise_error()
    return r

#endregion

#region NativeStringList

cimport libc.stdlib

cdef void* malloc(size_t size):
    return libc.stdlib.malloc(size)

cdef void free(const void* ptr):
    libc.stdlib.free(<void*>ptr)

cdef class NativeStringList:
    cdef object strings
    cdef const LPCWSTR* ptr

    def __init__(self, strings=None):
        self.strings = strings or []
        self.ptr = NULL
    
    cdef NativeStringList __enter__(self):
        ss = list(self.strings)
        cdef LPCWSTR *_ss = <LPCWSTR*>malloc(sizeof(LPCWSTR) * (len(ss) + 1))
        try:
            for i, s in enumerate(ss):
                _ss[i] = <LPCWSTR>s
            _ss[len(ss)] = <LPCWSTR>NULL

            self.ptr, _ss = _ss, NULL
        finally:
            if _ss:
                free(_ss)

        return self
    
    def __exit__(self, exc_type, exc_value, exc_tb):
        if self.ptr:
            free(self.ptr)

#endregion


cdef class _WinHTTPBase:
    cdef HINTERNET _handle

    cdef _set_handle(self, HINTERNET handle):
        if self._handle:
            raise RuntimeError("cannot set handle multiple times")
        if not handle:
            raise_error()

        cdef DWORD_PTR self_ptr = <DWORD_PTR><void*>self
        check_bool(WinHttpSetOption(
            handle,
            WINHTTP_OPTION_CONTEXT_VALUE,
            &self_ptr,
            sizeof(self_ptr)
        ))

        self._handle = handle

    def close(self):
        cdef HINTERNET h = self._handle
        self._handle = NULL
        if h and not WinHttpCloseHandle(h):
            raise_error()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.close()

    def _on_status(self, context, status, data):
        print("Unhandled: {} {}".format(status, data))


cdef class _WinHTTPRequest(_WinHTTPBase):
    cpdef readonly _WinHTTPConnection _connection
    cpdef object data
    cpdef object object_name

    def __init__(self, _WinHTTPConnection connection, object_name):
        self._connection = connection
        self.data = None
        self.object_name = object_name

    def __repr__(self):
        return "<" + ", ".join([
            type(self).__name__,
            f"host={self._connection.host}",
            f"port={self._connection.port}",
            f"url={self.object_name}",
        ]) + ">"

    def add_headers(self, str headers, merge_with=None):
        cdef DWORD merge = WINHTTP_ADDREQ_FLAG_ADD
        if merge_with == '':
            merge |= WINHTTP_ADDREQ_FLAG_COALESCE
        elif merge_with == ',':
            merge |= WINHTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA
        elif merge_with == ';':
            merge |= WINHTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON
        elif merge_with:
            raise ValueError("merge_with must be None, '', ',' or ';'")

        check_bool(WinHttpAddRequestHeaders(
            self._handle,
            headers,
            -1,
            merge
        ))

    def set_headers(self, str headers):
        check_bool(WinHttpAddRequestHeaders(
            self._handle,
            headers,
            -1,
            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE
        ))

    def set_data(self, bytes data):
        self.data = data

    def send(self):
        data_len = 0
        if self.data:
            data = memoryview('b', self.data)
            data_len = len(data)
            self.set_headers("Content-Length: {}".format(data_len))
            if data_len > 2**32:
                data_len = WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH

        check_bool(WinHttpSendRequest(
            self._handle,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            <DWORD>data_len,
            <size_t><const void*>self
        ))

        check_bool(WinHttpReceiveResponse(
            self._handle,
            NULL
        ))

    def read_headers(self, request_only=True):
        cdef DWORD buffer_len = 0

        cdef DWORD query = WINHTTP_QUERY_RAW_HEADERS
        if request_only:
            query |= WINHTTP_QUERY_FLAG_REQUEST_HEADERS

        WinHttpQueryHeaders(
            self._handle,
            query,
            WINHTTP_HEADER_NAME_BY_INDEX,
            WINHTTP_NO_OUTPUT_BUFFER,
            &buffer_len,
            WINHTTP_NO_HEADER_INDEX,
        )
        if not buffer_len and GetLastError():
            raise_error()

        data = bytearray(buffer_len)

        check_bool(WinHttpQueryHeaders(
            self._handle,
            query,
            WINHTTP_HEADER_NAME_BY_INDEX,
            <unsigned char*>data,
            &buffer_len,
            WINHTTP_NO_HEADER_INDEX,
        ))

        return data[:buffer_len].decode('utf-16-le').split('\0')

    def read1(self):
        data = bytearray(8192)
        cdef DWORD cbread = 0

        check_bool(WinHttpReadData(
            self._handle,
            <unsigned char*>data,
            len(data),
            &cbread
        ))

        return data[:cbread]

    def _on_status(self, context, status, data):
        print("{}: {} {}".format(self, status, data))

cdef class _WinHTTPConnection(_WinHTTPBase):
    cpdef readonly _WinHTTPSession _session
    cpdef readonly bint secure
    cpdef readonly object host, port

    def __init__(self, _WinHTTPSession _session, host, port):
        self._session = _session
        self.secure = False
        self.host = host
        self.port = port

    def __repr__(self):
        return "<" + ", ".join([
            type(self).__name__,
            f"host={self.host}",
            f"port={self.port}",
            f"secure={self.secure}",
        ]) + ">"

    def open(self, str method, str object_name, str version, str referer, accept_types):
        cdef HINTERNET handle

        cdef LPCWSTR _version = NULL
        if version:
            _version = version
        cdef LPCWSTR _referer = NULL
        if referer:
            _referer = referer

        conn = _WinHTTPRequest(self, object_name)

        with NativeStringList(accept_types) as _accept:
            conn._set_handle(WinHttpOpenRequest(
                self._handle,
                method.upper(),
                object_name,
                _version,
                _referer,
                _accept.ptr,
                WINHTTP_FLAG_SECURE if self.secure else 0
            ))

        return conn

cdef class _WinHTTPSession(_WinHTTPBase):
    def __init__(self, str agent):
        self._set_handle(WinHttpOpen(
            agent,
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            NULL,
            WINHTTP_NO_PROXY_BYPASS,
            0
        ))

        cdef WINHTTP_STATUS_CALLBACK cb = WINHTTP_INVALID_STATUS_CALLBACK
        try:
            cb = WinHttpSetStatusCallback(
                self._handle,
                <WINHTTP_STATUS_CALLBACK>_on_status_cb,
                WINHTTP_CALLBACK_FLAG_REQUEST_ERROR |
                    #WINHTTP_CALLBACK_FLAG_HEADERS_AVAILABLE |
                    #WINHTTP_CALLBACK_FLAG_DATA_AVAILABLE |
                    #WINHTTP_CALLBACK_FLAG_READ_COMPLETE |
                    #WINHTTP_CALLBACK_FLAG_RESOLVE_NAME |
                    #WINHTTP_CALLBACK_FLAG_REDIRECT |
                    #WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS |
                    WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS |
                    0,
                0
            )
            if cb == WINHTTP_INVALID_STATUS_CALLBACK:
                raise_error()
        except:
            self.close()
            raise

    def connect(self, str server_name, INTERNET_PORT port=INTERNET_DEFAULT_PORT, bint use_ssl=False):
        cdef HINTERNET handle

        if use_ssl and port == INTERNET_DEFAULT_PORT:
            port = INTERNET_DEFAULT_HTTPS_PORT

        conn = _WinHTTPConnection(self, server_name, port)
        conn._set_handle(WinHttpConnect(
            self._handle,
            server_name,
            port,
            0
        ))
        conn.secure = use_ssl

        return conn


def urlsplit(str url):
    cdef URL_COMPONENTS res

    ZeroMemory(&res, sizeof(res))
    res.dwStructSize = sizeof(res)
    # Just have to initialize the contents, and these will be
    # overwritten by the function call
    res.dwSchemeLength = res.dwHostNameLength = res.dwUserNameLength = <DWORD>-1
    res.dwPasswordLength = res.dwUrlPathLength = res.dwExtraInfoLength = <DWORD>-1

    check_bool(WinHttpCrackUrl(
        url,
        0,
        0,
        &res
    ))

    query, _, fragment = res.lpszExtraInfo[:res.dwExtraInfoLength].rpartition('#')
    if query and query[0] == "?":
        query = query[1:]

    netloc = res.lpszHostName[:res.dwHostNameLength] if res.dwHostNameLength and res.dwSchemeLength else ""
    username = res.lpszUserName[:res.dwUserNameLength] if res.dwUserNameLength else ""
    password = res.lpszPassword[:res.dwPasswordLength] if res.dwPasswordLength else ""

    if netloc:
        if res.nPort:
            netloc = "{}:{}".format(netloc, res.nPort)
        if username or password:
            netloc = "{}:{}@{}".format(username, password, netloc)

    return (
        res.lpszScheme[:res.dwSchemeLength],
        netloc,
        res.lpszUrlPath[:res.dwUrlPathLength],
        query,
        fragment,
        username,
        password,
        res.lpszHostName[:res.dwHostNameLength].lower(),
        res.nPort,
    )

def urlunsplit(parts):
    # str scheme, str netloc, str path, str query, str fragment, str username, str password, str host, int port
    cdef URL_COMPONENTS res
    ipart = iter(parts)

    scheme = next(ipart)
    netloc = next(ipart, "")
    path = next(ipart, "")
    query = next(ipart, "")
    fragment = next(ipart, "")
    username = next(ipart, "")
    password = next(ipart, "")
    host = next(ipart, "")
    port = next(ipart, 0)

    if netloc and not host:
        host, _, port = netloc.rpartition(':')
        port = int(port) if port else 0

    extra = ""
    if query:
        extra += "?" + query
    if fragment:
        extra += "#" + fragment

    res.dwStructSize = sizeof(res)
    res.lpszScheme = scheme
    res.dwSchemeLength = <DWORD>len(scheme)
    res.lpszHostName = host
    res.dwHostNameLength = <DWORD>len(host)
    res.nPort = <INTERNET_PORT>port
    res.lpszUserName = username
    res.dwUserNameLength = <DWORD>len(username)
    res.lpszPassword = password
    res.dwPasswordLength = <DWORD>len(password)
    res.lpszUrlPath = path
    res.dwUrlPathLength = <DWORD>len(path)
    res.lpszExtraInfo = extra
    res.dwExtraInfoLength = <DWORD>len(extra)

    url = bytearray(256 * sizeof(Py_UNICODE))
    cdef DWORD url_len = 255
    if not WinHttpCreateUrl(&res, 0, <LPWSTR><unsigned char*>url, &url_len):
        if GetLastError() != ERROR_INSUFFICIENT_BUFFER:
            raise_error()
        url = bytearray((url_len + 1) * sizeof(Py_UNICODE))
        check_bool(WinHttpCreateUrl(&res, 0, <LPWSTR><unsigned char*>url, &url_len))
    return url[:url_len * sizeof(Py_UNICODE)].decode('utf-16-le')

cdef void _on_status_cb(
    HINTERNET hInternet,
    DWORD_PTR dwContext,
    DWORD dwInternetStatus,
    LPVOID lpvStatusInformation,
    DWORD dwStatusInformationLength
) nogil:
    cdef const WINHTTP_ASYNC_RESULT *res
    if dwInternetStatus == WINHTTP_CALLBACK_STATUS_HANDLE_CREATED:
        return

    with gil:
        status, handler = STATUS_MAP.get(dwInternetStatus)
        target = <object><void*>dwContext

        data = None
        if handler is str:
            data = <str>((<const Py_UNICODE*>lpvStatusInformation)[:dwStatusInformationLength])
        elif handler is int and sizeof(DWORD) == dwStatusInformationLength:
            data = <int>((<const DWORD*>lpvStatusInformation)[0])
        elif handler is not None:
            data = handler(<DWORD_PTR>lpvStatusInformation, dwStatusInformationLength)

        target._on_status(
            dwContext,
            status,
            data
        )
