"""Public certificate normalization and bounded proxy certificate retrieval."""
import http.server
import os
import ssl
import threading
import unittest
from unittest.mock import patch
from repack.certificates import decode_public, MAX_CERTIFICATE
from repack.proxy_certificate import fetch_certificate

# Public test certificate only; no private key is shipped.
PEM = '-----BEGIN CERTIFICATE-----\nMIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5\nMQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g\nUm9vdCBDQSAzMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG\nA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg\nQ0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG8lKl\nui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt6j\nQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSr\nttvXBp43rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkr\nBqWTrBqYaGFy+uGh0PsceGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteM\nYyRIHN8wfdVoOw==\n-----END CERTIFICATE-----\n'
DER = ssl.PEM_cert_to_DER_cert(PEM)


class Certificates(unittest.TestCase):
    def test_pem_and_der_normalize_to_same_public_identity(self):
        pem=decode_public(PEM.encode());der=decode_public(DER)
        self.assertEqual(pem['sha256'],der['sha256'])
        self.assertEqual(pem['der'],DER);self.assertEqual(der['pem'],PEM.encode())
        self.assertEqual((pem['format'],der['format']),('PEM','DER'))

    def test_private_mixed_multiple_and_malformed_inputs_are_refused(self):
        for data in (b'', b'html', PEM.encode()*2, DER+b'extra', DER+DER,
                     PEM.encode()+b'-----BEGIN PRIVATE KEY-----\nsecret',
                     b'-----BEGIN CERTIFICATE-----\nYm9ndXM=\n-----END CERTIFICATE-----',
                     b'x'*(MAX_CERTIFICATE+1)):
            with self.subTest(length=len(data)):
                with self.assertRaises(ValueError):decode_public(data)


class ProxyCertificate(unittest.TestCase):
    def setUp(self):
        test=self;self.payload=DER;self.redirect=False;self.requests=0
        class Handler(http.server.BaseHTTPRequestHandler):
            server_version='Burp Suite';sys_version=''
            def log_message(self,*args):pass
            def do_GET(self):
                test.requests+=1
                self.send_response(302 if test.redirect else 200)
                if test.redirect:self.send_header('Location','/unexpected')
                self.end_headers()
                try:self.wfile.write(test.payload)
                except (BrokenPipeError,ConnectionResetError):pass
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.url='http://127.0.0.1:'+str(self.server.server_port)+'/cert'
        self.addCleanup(self.close)
    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join()
    def test_der_download_bypasses_proxy_environment_and_normalizes(self):
        with patch.dict(os.environ,{'http_proxy':'http://127.0.0.1:1','HTTP_PROXY':'http://127.0.0.1:1','NO_PROXY':'','no_proxy':''}):
            result=fetch_certificate(self.url)
        self.assertEqual(result['provider'],'Burp Suite');self.assertEqual(result['pem'],PEM.encode())
        self.assertEqual(result['format'],'DER');self.assertEqual(result['url'],self.url)
    def test_pem_download(self):
        self.payload=PEM.encode();self.assertEqual(fetch_certificate(self.url)['der'],DER)
    def test_html_oversize_and_redirect_are_rejected(self):
        for data in (b'<html>Proxy page</html>',b'x'*(MAX_CERTIFICATE+1)):
            self.payload=data
            with self.assertRaises(ValueError):fetch_certificate(self.url)
        self.redirect=True;self.requests=0
        with self.assertRaises(ValueError):fetch_certificate(self.url)
        self.assertEqual(self.requests,1)
    def test_only_http_urls_without_credentials(self):
        for url in ('file:///etc/passwd','ftp://example.com/cert','http://user:pass@localhost/cert',
                    'http://localhost/cert#fragment','http://localhost:99999/cert','http://localhost/ certificate'):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):fetch_certificate(url)
        self.assertEqual(self.requests,0)

if __name__=='__main__':unittest.main()
