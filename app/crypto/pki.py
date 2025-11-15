# app/crypto/pki.py
"""
X.509 validation: signed-by-CA, validity window, CN/SAN.
Used in the Control Plane (hello exchange) for mutual authentication.
"""

import os
from datetime import datetime, timezone
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import Certificate

backend = default_backend()

# ----------------------------------------------------------------------
# Low-level helpers
# ----------------------------------------------------------------------
def load_certificate(pem_path: str) -> Certificate:
    """Load an X.509 certificate from a PEM file."""
    if not os.path.exists(pem_path):
        raise FileNotFoundError(f"Certificate not found: {pem_path}")
    with open(pem_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), backend)


def load_ca_certificate(ca_pem_path: str) -> Certificate:
    """Load the trusted Root CA certificate."""
    return load_certificate(ca_pem_path)


def verify_signature(ca_cert: Certificate, leaf_cert: Certificate) -> bool:
    """Verify that leaf_cert is signed by ca_cert (SHA-256 + PKCS#1 v1.5)."""
    if leaf_cert.issuer != ca_cert.subject:
        return False

    pub: RSAPublicKey = ca_cert.public_key()
    try:
        pub.verify(
            leaf_cert.signature,
            leaf_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
    except Exception as exc:
        raise ValueError(f"Signature verification error: {exc}") from exc


def check_validity(cert: Certificate) -> bool:
    """Return True if the current UTC time is inside the cert's validity window."""
    now = datetime.now(timezone.utc)
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def get_common_name(cert: Certificate) -> Optional[str]:
    """Extract the Common Name (CN) from the Subject."""
    for attr in cert.subject:
        if attr.oid == x509.NameOID.COMMON_NAME:
            return attr.value
    return None


def get_san_dns_names(cert: Certificate) -> List[str]:
    """Return a list of DNSName entries from the SAN extension (empty if missing)."""
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def verify_identity(cert: Certificate, expected_hostname: str) -> bool:
    """Match the expected hostname against CN or SAN."""
    if get_common_name(cert) == expected_hostname:
        return True
    return expected_hostname in get_san_dns_names(cert)


def is_ca_certificate(cert: Certificate) -> bool:
    """Check BasicConstraints ca=True."""
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return bc.value.ca is True
    except x509.ExtensionNotFound:
        return False


# ----------------------------------------------------------------------
# NEW: Extract RSA public key from X.509 certificate
# ----------------------------------------------------------------------
def extract_public_key_from_cert(cert_pem: str) -> str:
    """
    Extract RSA public key in PEM format from an X.509 certificate.
    Used for signature verification of chat messages.
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"), backend)
    pub_key = cert.public_key()
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


# ----------------------------------------------------------------------
# Full validation (used for file-based certs)
# ----------------------------------------------------------------------
def validate_certificate(
    leaf_pem_path: str,
    ca_pem_path: str,
    expected_hostname: str,
) -> Certificate:
    """Complete PKI validation used in manual tests or config loading."""
    ca_cert = load_ca_certificate(ca_pem_path)
    leaf_cert = load_certificate(leaf_pem_path)

    if not verify_signature(ca_cert, leaf_cert):
        raise ValueError("Leaf certificate is NOT signed by the trusted CA")
    if not is_ca_certificate(ca_cert):
        raise ValueError("Trusted CA certificate lacks BasicConstraints ca=True")
    if not check_validity(leaf_cert):
        raise ValueError(
            f"Leaf certificate outside validity window: "
            f"{leaf_cert.not_valid_before_utc} to {leaf_cert.not_valid_after_utc}"
        )
    if not verify_identity(leaf_cert, expected_hostname):
        cn = get_common_name(leaf_cert) or "None"
        san = get_san_dns_names(leaf_cert)
        raise ValueError(
            f"Hostname mismatch – expected: {expected_hostname} | "
            f"CN: {cn} | SAN DNS: {san}"
        )
    return leaf_cert


# ----------------------------------------------------------------------
# Helpers that work with PEM strings (hello messages)
# ----------------------------------------------------------------------
def validate_server_certificate(
    server_cert_pem: str,
    ca_pem_path: str,
    expected_server_name: str,
) -> Certificate:
    """Client-side validation of the server certificate."""
    ca_cert = load_ca_certificate(ca_pem_path)
    cert = x509.load_pem_x509_certificate(server_cert_pem.encode("utf-8"), backend)

    if not verify_signature(ca_cert, cert):
        raise ValueError("Server certificate not signed by trusted CA")
    if not check_validity(cert):
        raise ValueError("Server certificate expired or not yet valid")
    if not verify_identity(cert, expected_server_name):
        raise ValueError(f"Server identity mismatch: {expected_server_name}")

    return cert


def validate_client_certificate(
    client_cert_pem: str,
    ca_pem_path: str,
    expected_client_name: Optional[str] = None,
) -> Certificate:
    """Server-side validation of the client certificate."""
    ca_cert = load_ca_certificate(ca_pem_path)
    cert = x509.load_pem_x509_certificate(client_cert_pem.encode("utf-8"), backend)

    if not verify_signature(ca_cert, cert):
        raise ValueError("Client certificate not signed by trusted CA")
    if not check_validity(cert):
        raise ValueError("Client certificate expired or not yet valid")
    if expected_client_name and not verify_identity(cert, expected_client_name):
        raise ValueError(f"Client identity mismatch: {expected_client_name}")

    return cert


# ----------------------------------------------------------------------
# Simple CLI test
# ----------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("Usage: python -m app.crypto.pki <leaf.pem> <ca.pem> <expected_hostname>")
        sys.exit(1)

    leaf_path, ca_path, hostname = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        cert = validate_certificate(leaf_path, ca_path, hostname)
        print(f"Certificate VALID for {hostname}")
        print(f"  Subject : {cert.subject}")
        print(f"  Expires : {cert.not_valid_after_utc}")
    except Exception as exc:
        print(f"Validation FAILED: {exc}")

# to run this script: python -m app.crypto.pki certs/myserver.example.com_cert.pem certs/MyRootCA_ca_cert.pem myserver.example.com