"""Local fixture oracle. Answer controlled paths without contacting an upstream."""
import json
import os
from pathlib import Path
import re

from mitmproxy import http


def request(flow: http.HTTPFlow):
    request = flow.request
    token = re.fullmatch(r'/repack/([A-Za-z0-9_-]{8,120})', request.path)
    if not token or (request.host != '127.0.0.1' and not request.host.endswith('.repack.test')):
        flow.response = http.Response.make(403, b'Fixture endpoint only')
        return
    event = {'kind': 'http', 'timestamp_start': request.timestamp_start, 'method': request.method,
             'scheme': request.scheme, 'port': request.port, 'token': token[1], 'host': request.host, 'path': request.path,
             'tls': bool(flow.client_conn.tls_established)}
    with Path(os.environ['REPACK_ORACLE_LOG']).open('a') as stream:
        stream.write(json.dumps(event, sort_keys=True) + '\n')
        stream.flush()
    flow.response = http.Response.make(200, json.dumps({'token': token[1], 'via': 'proxy'}).encode(),
                                       {'Content-Type': 'application/json', 'Connection': 'close'})
