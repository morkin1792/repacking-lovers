"""Bounded public X.509 input; normalize PEM and DER without private material."""
import hashlib
import re
import ssl

MAX_CERTIFICATE = 1024 * 1024


def decode_public(data: bytes):
    if not data or len(data) > MAX_CERTIFICATE:
        raise ValueError('Choose one public X.509 certificate, at most 1 MiB')
    encoding = 'DER'
    if b'-----BEGIN' in data:
        encoding = 'PEM'
        try:
            text = data.decode('ascii')
            match = re.fullmatch(r'\s*(-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----)\s*', text)
            if not match:
                raise ValueError('CA must contain exactly one public PEM certificate and no private key')
            der = ssl.PEM_cert_to_DER_cert(match[1])
        except (UnicodeError, ssl.SSLError) as error:
            raise ValueError('Choose a public X.509 certificate in PEM or DER format') from error
    else:
        der = data
    try:
        # Enforce one exact ASN.1 object, rejecting concatenated/trailing material.
        if len(der) < 2 or der[0] != 0x30:
            raise ValueError('Invalid certificate envelope')
        length, header = der[1], 2
        if length & 0x80:
            count = length & 0x7f
            if not 1 <= count <= 4 or len(der) < 2 + count:
                raise ValueError('Invalid certificate length')
            length = int.from_bytes(der[2:2 + count], 'big'); header += count
        if header + length != len(der):
            raise ValueError('Choose exactly one certificate, without trailing data')
        pem = ssl.DER_cert_to_PEM_cert(der)
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=pem)
    except (ssl.SSLError, ValueError) as error:
        raise ValueError('CA is not one valid public X.509 certificate in PEM or DER format') from error
    return {'sha256': hashlib.sha256(der).hexdigest(), 'der': der, 'pem': pem.encode('ascii'), 'format': encoding}
