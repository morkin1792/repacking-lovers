"""Fetch only a public proxy certificate; never route this request through a proxy."""
import urllib.error
import urllib.parse
import urllib.request
from .certificates import decode_public, MAX_CERTIFICATE

DEFAULT_URL = 'http://127.0.0.1:8080/cert'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_certificate(url=DEFAULT_URL, timeout=3):
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError('Enter an HTTP(S) certificate URL')
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or any(c.isspace() for c in url)):
        raise ValueError('Use an HTTP(S) certificate URL without credentials or fragments')
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError('Invalid certificate URL port')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(urllib.request.Request(url, headers={'Accept': 'application/pkix-cert, application/x-x509-ca-cert, application/octet-stream, application/x-pem-file'}), timeout=timeout) as response:
            data = response.read(MAX_CERTIFICATE + 1)
            server = response.headers.get('Server', '')
        result = decode_public(data)
    except (urllib.error.URLError, OSError, TimeoutError) as error:
        if isinstance(error, urllib.error.HTTPError): error.close()
        raise ValueError('Could not download the proxy certificate. Start Burp, change the certificate URL, or upload a PEM/DER file.') from error
    return {**result, 'url': url, 'provider': 'Burp Suite' if any(s in server.casefold() for s in ('burp', 'portswigger')) else 'Proxy certificate'}
