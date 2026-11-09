"""Operator-owned upstream proxy capture: metadata only, with an explicit optional identifying header."""
import json
import os
from pathlib import Path
import re
from mitmproxy import http

OUTPUT = Path(os.environ['REPACK_CAPTURE_LOG'])
OUTPUT.parent.mkdir(parents=True, exist_ok=True)
_descriptor = os.open(OUTPUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.close(_descriptor)
HEADER = os.environ.get('REPACK_IDENTIFYING_HEADER')
if HEADER:
    name, separator, value = HEADER.partition(':')
    if not separator or not re.fullmatch(r'[A-Za-z0-9-]{1,80}', name) or not value.strip() or any(c in value for c in '\r\n'):
        raise ValueError('Invalid explicit identifying header')
    HEADER = (name, value.strip())


def emit(row):
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open('a') as stream: stream.write(json.dumps(row, sort_keys=True) + '\n')


def http_connect(flow: http.HTTPFlow):
    request = flow.request
    emit({'kind': 'connect', 'flow_id': flow.id, 'timestamp_start': request.timestamp_start,
          'scheme': request.scheme, 'host': request.host, 'port': request.port, 'method': 'CONNECT',
          'path': '', 'tls': False})


def request(flow: http.HTTPFlow):
    if HEADER: flow.request.headers[HEADER[0]] = HEADER[1]


def response(flow: http.HTTPFlow):
    request = flow.request
    emit({'kind': 'http', 'flow_id': flow.id, 'timestamp_start': request.timestamp_start,
          'scheme': request.scheme, 'host': request.host, 'port': request.port, 'method': request.method,
          'path': request.path.split('?', 1)[0], 'tls': bool(flow.client_conn.tls_established),
          'status_code': flow.response.status_code})


def error(flow: http.HTTPFlow):
    request = flow.request
    emit({'kind': 'error', 'flow_id': flow.id, 'timestamp_start': request.timestamp_start,
          'scheme': request.scheme, 'host': request.host, 'port': request.port, 'method': request.method,
          'path': request.path.split('?', 1)[0], 'tls': bool(flow.client_conn.tls_established)})
