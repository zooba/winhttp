
# cython: language_level=3
# distutils: libraries = winhttp

cdef extern from "windows.h":
    ctypedef bint BOOL
    ctypedef int WORD
    ctypedef int DWORD
    ctypedef int* LPDWORD
    ctypedef int UINT
    ctypedef size_t DWORD_PTR
    ctypedef size_t UINT_PTR
    ctypedef Py_UNICODE* LPWSTR
    ctypedef const Py_UNICODE* LPCWSTR
    ctypedef void* LPVOID
    ctypedef void* HANDLE

    void ZeroMemory(void*, UINT) nogil
    DWORD GetLastError() nogil

    DWORD ERROR_NOT_ENOUGH_MEMORY
    DWORD ERROR_INVALID_PARAMETER
    DWORD ERROR_INSUFFICIENT_BUFFER

cdef extern from "winhttp.h":
    ctypedef void* HINTERNET
    ctypedef unsigned int INTERNET_PORT

    HINTERNET WinHttpOpen(
        LPCWSTR pszAgentW,
        DWORD   dwAccessType,
        LPCWSTR pszProxyW,
        LPCWSTR pszProxyBypassW,
        DWORD   dwFlags
    ) nogil

    DWORD WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
    DWORD WINHTTP_ACCESS_TYPE_DEFAULT_PROXY

    LPCWSTR WINHTTP_NO_PROXY_BYPASS

    DWORD WINHTTP_FLAG_ASYNC

    BOOL WinHttpQueryOption(
        HINTERNET hInternet,
        DWORD     dwOption,
        LPVOID    lpBuffer,
        LPDWORD   lpdwBufferLength
    ) nogil

    BOOL WinHttpSetOption(
        HINTERNET hInternet,
        DWORD     dwOption,
        LPVOID    lpBuffer,
        DWORD     dwBufferLength
    ) nogil

    DWORD WINHTTP_OPTION_CONTEXT_VALUE

    ctypedef void (*WINHTTP_STATUS_CALLBACK)(
        HINTERNET hInternet,
        DWORD_PTR dwContext,
        DWORD dwInternetStatus,
        LPVOID lpvStatusInformation,
        DWORD dwStatusInformationLength
    )

    WINHTTP_STATUS_CALLBACK WinHttpSetStatusCallback(
        HINTERNET               hInternet,
        WINHTTP_STATUS_CALLBACK lpfnInternetCallback,
        DWORD                   dwNotificationFlags,
        DWORD_PTR               dwReserved
    ) nogil

    DWORD WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS
    DWORD WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS
    DWORD WINHTTP_CALLBACK_FLAG_RESOLVE_NAME
    DWORD WINHTTP_CALLBACK_FLAG_CONNECT_TO_SERVER
    DWORD WINHTTP_CALLBACK_FLAG_DETECTING_PROXY
    DWORD WINHTTP_CALLBACK_FLAG_DATA_AVAILABLE
    DWORD WINHTTP_CALLBACK_FLAG_HEADERS_AVAILABLE
    DWORD WINHTTP_CALLBACK_FLAG_READ_COMPLETE
    DWORD WINHTTP_CALLBACK_FLAG_REQUEST_ERROR
    DWORD WINHTTP_CALLBACK_FLAG_SEND_REQUEST
    DWORD WINHTTP_CALLBACK_FLAG_SENDREQUEST_COMPLETE
    DWORD WINHTTP_CALLBACK_FLAG_WRITE_COMPLETE
    DWORD WINHTTP_CALLBACK_FLAG_RECEIVE_RESPONSE
    DWORD WINHTTP_CALLBACK_FLAG_CLOSE_CONNECTION
    DWORD WINHTTP_CALLBACK_FLAG_HANDLES
    DWORD WINHTTP_CALLBACK_FLAG_REDIRECT
    DWORD WINHTTP_CALLBACK_FLAG_INTERMEDIATE_RESPONSE
    DWORD WINHTTP_CALLBACK_FLAG_SECURE_FAILURE

    WINHTTP_STATUS_CALLBACK WINHTTP_INVALID_STATUS_CALLBACK

    HINTERNET WinHttpConnect(
        HINTERNET     hSession,
        LPCWSTR       pswzServerName,
        INTERNET_PORT nServerPort,
        DWORD         dwReserved
    ) nogil

    INTERNET_PORT INTERNET_DEFAULT_HTTP_PORT
    INTERNET_PORT INTERNET_DEFAULT_HTTPS_PORT
    INTERNET_PORT INTERNET_DEFAULT_PORT

    HINTERNET WinHttpOpenRequest(
        HINTERNET hConnect,
        LPCWSTR   pwszVerb,
        LPCWSTR   pwszObjectName,
        LPCWSTR   pwszVersion,
        LPCWSTR   pwszReferrer,
        LPCWSTR  *ppwszAcceptTypes,
        DWORD     dwFlags
    ) nogil

    LPCWSTR WINHTTP_NO_REFERER

    DWORD WINHTTP_FLAG_SECURE

    BOOL WinHttpAddRequestHeaders(
        HINTERNET hRequest,
        LPCWSTR   lpszHeaders,
        DWORD     dwHeadersLength,
        DWORD     dwModifiers
    ) nogil

    DWORD WINHTTP_ADDREQ_FLAG_ADD
    DWORD WINHTTP_ADDREQ_FLAG_ADD_IF_NEW
    DWORD WINHTTP_ADDREQ_FLAG_COALESCE
    DWORD WINHTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA
    DWORD WINHTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON
    DWORD WINHTTP_ADDREQ_FLAG_REPLACE

    BOOL WinHttpReceiveResponse(
        HINTERNET hRequest,
        LPVOID    lpReserved
    ) nogil

    BOOL WinHttpQueryHeaders(
        HINTERNET hRequest,
        DWORD     dwInfoLevel,
        LPCWSTR   pwszName,
        LPVOID    lpBuffer,
        LPDWORD   lpdwBufferLength,
        LPDWORD   lpdwIndex
    ) nogil

    DWORD WINHTTP_QUERY_RAW_HEADERS
    DWORD WINHTTP_QUERY_RAW_HEADERS_CRLF
    DWORD WINHTTP_QUERY_FLAG_REQUEST_HEADERS
    LPCWSTR WINHTTP_HEADER_NAME_BY_INDEX
    LPVOID WINHTTP_NO_OUTPUT_BUFFER
    LPDWORD WINHTTP_NO_HEADER_INDEX

    BOOL WinHttpReadData(
        HINTERNET hRequest,
        LPVOID    lpBuffer,
        DWORD     dwNumberOfBytesToRead,
        LPDWORD   lpdwNumberOfBytesRead
    ) nogil

    BOOL WinHttpSendRequest(
        HINTERNET hRequest,
        LPCWSTR   lpszHeaders,
        DWORD     dwHeadersLength,
        LPVOID    lpOptional,
        DWORD     dwOptionalLength,
        DWORD     dwTotalLength,
        DWORD_PTR dwContext
    ) nogil

    DWORD WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH

    LPCWSTR WINHTTP_NO_ADDITIONAL_HEADERS
    LPCWSTR WINHTTP_NO_REQUEST_DATA


    BOOL WinHttpCloseHandle(HINTERNET handle) nogil

    ctypedef struct WINHTTP_ASYNC_RESULT:
        DWORD_PTR dwResult
        DWORD     dwError

    ctypedef struct URL_COMPONENTS:
        DWORD           dwStructSize
        LPWSTR          lpszScheme
        DWORD           dwSchemeLength
        DWORD           nScheme
        LPWSTR          lpszHostName
        DWORD           dwHostNameLength
        INTERNET_PORT   nPort
        LPWSTR          lpszUserName
        DWORD           dwUserNameLength
        LPWSTR          lpszPassword
        DWORD           dwPasswordLength
        LPWSTR          lpszUrlPath
        DWORD           dwUrlPathLength
        LPWSTR          lpszExtraInfo
        DWORD           dwExtraInfoLength

    BOOL WinHttpCrackUrl(
        LPCWSTR          pwszUrl,
        DWORD            dwUrlLength,
        DWORD            dwFlags,
        URL_COMPONENTS  *lpUrlComponents
    ) nogil

    BOOL WinHttpCreateUrl(
        URL_COMPONENTS  *lpUrlComponents,
        DWORD            dwFlags,
        LPWSTR           pwszUrl,
        LPDWORD          pdwUrlLength
    ) nogil

    DWORD ICU_DECODE
    DWORD ICU_ENCODE
    DWORD ICU_REJECT_USERPWD

    DWORD INTERNET_SCHEME_HTTP
    DWORD INTERNET_SCHEME_HTTPS

    DWORD WINHTTP_CALLBACK_STATUS_CLOSING_CONNECTION
    DWORD WINHTTP_CALLBACK_STATUS_CONNECTED_TO_SERVER
    DWORD WINHTTP_CALLBACK_STATUS_CONNECTING_TO_SERVER
    DWORD WINHTTP_CALLBACK_STATUS_CONNECTION_CLOSED
    DWORD WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE
    DWORD WINHTTP_CALLBACK_STATUS_HANDLE_CREATED
    DWORD WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING
    DWORD WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE
    DWORD WINHTTP_CALLBACK_STATUS_INTERMEDIATE_RESPONSE
    DWORD WINHTTP_CALLBACK_STATUS_NAME_RESOLVED
    DWORD WINHTTP_CALLBACK_STATUS_READ_COMPLETE
    DWORD WINHTTP_CALLBACK_STATUS_RECEIVING_RESPONSE
    DWORD WINHTTP_CALLBACK_STATUS_REDIRECT
    DWORD WINHTTP_CALLBACK_STATUS_REQUEST_ERROR
    DWORD WINHTTP_CALLBACK_STATUS_REQUEST_SENT
    DWORD WINHTTP_CALLBACK_STATUS_RESOLVING_NAME
    DWORD WINHTTP_CALLBACK_STATUS_RESPONSE_RECEIVED
    DWORD WINHTTP_CALLBACK_STATUS_SECURE_FAILURE
    DWORD WINHTTP_CALLBACK_STATUS_SENDING_REQUEST
    DWORD WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE
    DWORD WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE
    DWORD WINHTTP_CALLBACK_STATUS_GETPROXYFORURL_COMPLETE
    DWORD WINHTTP_CALLBACK_STATUS_CLOSE_COMPLETE
    DWORD WINHTTP_CALLBACK_STATUS_SHUTDOWN_COMPLETE

    DWORD API_RECEIVE_RESPONSE
    DWORD API_QUERY_DATA_AVAILABLE
    DWORD API_READ_DATA
    DWORD API_WRITE_DATA
    DWORD API_SEND_REQUEST

    DWORD ERROR_WINHTTP_INCORRECT_HANDLE_TYPE
    DWORD ERROR_WINHTTP_INTERNAL_ERROR
    DWORD ERROR_WINHTTP_INVALID_URL
    DWORD ERROR_WINHTTP_OPERATION_CANCELLED
    DWORD ERROR_WINHTTP_UNRECOGNIZED_SCHEME
    DWORD ERROR_WINHTTP_CANNOT_CONNECT
    DWORD ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED
    DWORD ERROR_WINHTTP_CONNECTION_ERROR
    DWORD ERROR_WINHTTP_INCORRECT_HANDLE_STATE
    DWORD ERROR_WINHTTP_LOGIN_FAILURE
    DWORD ERROR_WINHTTP_NAME_NOT_RESOLVED
    DWORD ERROR_WINHTTP_RESPONSE_DRAIN_OVERFLOW
    DWORD ERROR_WINHTTP_SECURE_FAILURE
    DWORD ERROR_WINHTTP_SHUTDOWN
    DWORD ERROR_WINHTTP_TIMEOUT
    DWORD ERROR_WINHTTP_RESEND_REQUEST

