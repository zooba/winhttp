from base64 import b64encode

from . import _winhttp
from requests import PreparedRequest, Response

from typing import Optional, Union


class WinHttpAdapter:
    def __init__(self):
        self._session = _winhttp._WinHttpSession()
        self._connections = {}

    def send(
        self,
        request: PreparedRequest,
        stream=False,
        timeout=None,
        verify=True,
        cert=None,
        proxies=None,
    ) -> Response:
        """Sends PreparedRequest object. Returns Response object.

        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param stream: (optional) Whether to stream the request content.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple
        :param verify: (not supported) Connections are always verified
        :param cert: (not supported) Any user-provided SSL certificate to be trusted.
        :param proxies: (not supported) The proxies dictionary to apply to the request.
        """

        if verify is not True:
            raise TypeError("{.__name__} requires verify=True".format(type(self)))
        if cert is not None:
            raise TypeError("{.__name__} does not support cert".format(type(self)))
        if proxies is not None:
            raise TypeError("{.__name__} does not support proxies".format(type(self)))

        # TODO: Send request

        response = Response()

        # Fallback to None if there's no status_code, for whatever reason.
        response.status_code = getattr(resp, "status", None)

        # Make headers case-insensitive.
        response.headers = CaseInsensitiveDict(getattr(resp, "headers", {}))

        # Set encoding.
        response.encoding = get_encoding_from_headers(response.headers)
        response.raw = resp
        response.reason = response.raw.reason

        if isinstance(req.url, bytes):
            response.url = req.url.decode("utf-8")
        else:
            response.url = req.url

        # Add new cookies from the server.
        extract_cookies_to_jar(response.cookies, req, resp)

        # Give the Response some context.
        response.request = req
        response.connection = self

        return response

    def close(self):
        """Cleans up adapter specific items."""
        raise NotImplementedError


def install(session):
    adapter = WinHttpAdapter()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
