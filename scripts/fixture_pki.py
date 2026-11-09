"""Owned local TLS fixture certificates. Run with the pinned proxy's Python environment."""
import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def main():
    os.umask(0o077)
    root = Path(__file__).resolve().parents[1] / '.work/keys/fixture-tls'
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    now = dt.datetime.now(dt.timezone.utc)
    def key(name):
        path = root / (name + '.key')
        if path.exists(): return serialization.load_pem_private_key(path.read_bytes(), password=None)
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        path.chmod(0o600)
        return private
    ca_key = key('origin-ca')
    ca_path = root / 'origin-ca.pem'
    if not ca_path.exists():
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Repack fixture origin CA')])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=2))
                .not_valid_after(now + dt.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
                .sign(ca_key, hashes.SHA256()))
        ca_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    ca = x509.load_pem_x509_certificate(ca_path.read_bytes())
    if ca.public_key().public_numbers() != ca_key.public_key().public_numbers(): raise RuntimeError('CA key mismatch')
    result = {'ca': str(ca_path), 'ca_sha256': ca.fingerprint(hashes.SHA256()).hex()}
    for name in ('origin-good', 'origin-wrong-pin'):
        private = key(name)
        path = root / (name + '.pem')
        if not path.exists():
            leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1')]))
                    .issuer_name(ca.subject).public_key(private.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - dt.timedelta(days=2)).not_valid_after(now + dt.timedelta(days=365))
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1')),
                        x509.DNSName('pinned.repack.test'), x509.DNSName('deep.pinned.repack.test')]), critical=False)
                    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                    .sign(ca_key, hashes.SHA256()))
            path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        leaf = x509.load_pem_x509_certificate(path.read_bytes())
        if leaf.public_key().public_numbers() != private.public_key().public_numbers(): raise RuntimeError('Leaf key mismatch')
        ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, padding.PKCS1v15(), leaf.signature_hash_algorithm)
        pin = base64.b64encode(hashlib.sha256(private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).digest()).decode()
        result[name] = {'certificate': str(path), 'key': str(root / (name + '.key')), 'spki_sha256_base64': pin,
                        'certificate_sha256': leaf.fingerprint(hashes.SHA256()).hex()}
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__': main()
