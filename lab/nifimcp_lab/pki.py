"""Local lab PKI: one CA, one server certificate and per-identity client certificates.

Everything here is generated fresh for each disposable lab and never reused.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

VALIDITY_DAYS = 30
IDENTITIES = {
    # name -> certificate subject CN. The DN string NiFi sees is "CN=<cn>".
    "admin": "nifimcp-lab-admin",
    "observer": "nifimcp-lab-observer",
    "restricted": "nifimcp-lab-restricted",
    "outsider": "nifimcp-lab-outsider",
}


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


@dataclass
class IssuedIdentity:
    name: str
    dn: str
    cert_path: Path
    key_path: Path
    fingerprint: str


def _issue(ca_key, ca_cert, subject_cn: str, *, server: bool, sans: list[str] | None = None):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject_cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
                if server
                else [ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
    )
    if sans:
        entries: list[x509.GeneralName] = []
        for san in sans:
            try:
                entries.append(x509.IPAddress(ipaddress.ip_address(san)))
            except ValueError:
                entries.append(x509.DNSName(san))
        builder = builder.add_extension(x509.SubjectAlternativeName(entries), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def create_lab_pki(pki_dir: Path, *, server_sans: list[str], store_password: str) -> dict:
    """Create CA, server keystore material and client identities under ``pki_dir``.

    Returns a JSON-serializable description (paths and fingerprints, no secrets).
    """
    pki_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(pki_dir, 0o700)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("NiFiMCP Disposable Lab CA"))
        .issuer_name(_name("NiFiMCP Disposable Lab CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    (pki_dir / "ca.pem").write_bytes(ca_cert.public_bytes(pem))
    _write_private(
        pki_dir / "ca.key.pem",
        ca_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    )

    server_key, server_cert = _issue(ca_key, ca_cert, "localhost", server=True, sans=server_sans)
    (pki_dir / "server.pem").write_bytes(server_cert.public_bytes(pem))
    keystore = pkcs12.serialize_key_and_certificates(
        b"nifi-key",
        server_key,
        server_cert,
        [ca_cert],
        serialization.BestAvailableEncryption(store_password.encode()),
    )
    _write_private(pki_dir / "keystore.p12", keystore)

    identities = {}
    for name, cn in IDENTITIES.items():
        key, cert = _issue(ca_key, ca_cert, cn, server=False)
        cert_path = pki_dir / f"{name}.crt.pem"
        key_path = pki_dir / f"{name}.key.pem"
        cert_path.write_bytes(cert.public_bytes(pem) + ca_cert.public_bytes(pem))
        _write_private(
            key_path,
            key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        )
        identities[name] = {
            "dn": f"CN={cn}",
            "cert_path": str(cert_path),
            "key_path": str(key_path),
            "fingerprint_sha256": fingerprint(cert),
        }
    return {
        "ca_path": str(pki_dir / "ca.pem"),
        "ca_fingerprint_sha256": fingerprint(ca_cert),
        "server_cert_path": str(pki_dir / "server.pem"),
        "server_fingerprint_sha256": fingerprint(server_cert),
        "server_sans": server_sans,
        "keystore_path": str(pki_dir / "keystore.p12"),
        "identities": identities,
        "validity_days": VALIDITY_DAYS,
    }
