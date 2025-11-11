# app/crypto/pki.py
#"""
#X.509 validation: signed-by-CA, validity window, CN/SAN.
#Used in the Control Plane (hello exchange) for mutual authentication.
#"""

#PURPOSE: Validate X.509 certificates signed by a trusted Root CA, check validity windows, and verify hostname identity (CN and SAN)

#these are required imports for this assignment
import os #for file operations
from datetime import datetime, timezone #for certificate validity window checks
from typing import List, Optional #for type hints

from cryptography import x509 #for X.509 certificate handling
from cryptography.hazmat.primitives import hashes, serialization #for serialization
from cryptography.hazmat.primitives.asymmetric import padding #for RSA signature verification
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey #for RSA public key type
from cryptography.hazmat.backends import default_backend #for default backend
from cryptography.exceptions import InvalidSignature #for catching invalid signature exceptions
from cryptography.x509 import Certificate #for Certificate type hints

backend = default_backend() #use default cryptography backend

# SECTION 1: Low-level helpers
# These functions perform basic certificate operations: loading, signature verification, validity checks, and identity extraction
# ======================================================================

def load_certificate(pem_path: str) -> Certificate:
    """Load an X.509 certificate from a PEM file."""
    if not os.path.exists(pem_path): #check if file exists
        raise FileNotFoundError(f"Certificate not found: {pem_path}")
    with open(pem_path, "rb") as f: #open in binary read mode
        return x509.load_pem_x509_certificate(f.read(), backend) #parse PEM format certificate


def load_ca_certificate(ca_pem_path: str) -> Certificate:
    """Load the trusted Root CA certificate."""
    return load_certificate(ca_pem_path) #reuse load_certificate helper


def verify_signature(ca_cert: Certificate, leaf_cert: Certificate) -> bool:
    """Verify that leaf_cert is signed by ca_cert (SHA-256 + PKCS#1 v1.5)."""
    if leaf_cert.issuer != ca_cert.subject: #issuer of leaf cert must match subject of CA cert
        return False

    pub: RSAPublicKey = ca_cert.public_key() #extract CA's public key
    try:
        pub.verify( #verify signature using CA's public key
            leaf_cert.signature, #the signature from leaf cert
            leaf_cert.tbs_certificate_bytes, #the signed data (To Be Signed certificate bytes)
            padding.PKCS1v15(), #PKCS#1 v1.5 padding scheme
            hashes.SHA256(), #signature algorithm used
        )
        return True #signature is valid
    except InvalidSignature: #signature verification failed
        return False
    except Exception as exc:          # pragma: no cover – unexpected error
        raise ValueError(f"Signature verification error: {exc}") from exc


def check_validity(cert: Certificate) -> bool:
    """Return True if the current UTC time is inside the cert's validity window."""
    now = datetime.now(timezone.utc)          #get current UTC time (timezone-aware)
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc #check if now is within validity period


def get_common_name(cert: Certificate) -> Optional[str]:
    """Extract the Common Name (CN) from the Subject."""
    for attr in cert.subject: #iterate through subject attributes
        if attr.oid == x509.NameOID.COMMON_NAME: #find CN attribute
            return attr.value #return CN value
    return None #CN not found


def get_san_dns_names(cert: Certificate) -> List[str]:
    """Return a list of DNSName entries from the SAN extension (empty if missing)."""
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName) #get SAN extension
        return san_ext.value.get_values_for_type(x509.DNSName) #extract all DNS names from SAN
    except x509.ExtensionNotFound: #SAN extension not present
        return [] #return empty list


def verify_identity(cert: Certificate, expected_hostname: str) -> bool:
    """
    Match the expected hostname against:
      1. Common Name (CN)
      2. Any DNSName in SubjectAlternativeName
    """
    if get_common_name(cert) == expected_hostname: #check if CN matches expected hostname
        return True
    return expected_hostname in get_san_dns_names(cert) #check if hostname is in SAN DNS names


def is_ca_certificate(cert: Certificate) -> bool:
    """Check BasicConstraints ca=True."""
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints) #get BasicConstraints extension
        return bc.value.ca is True #return True if ca=True
    except x509.ExtensionNotFound: #BasicConstraints extension not present
        return False #not a CA certificate


# SECTION 2: Full validation (used for file-based certs)
# Complete end-to-end validation: signature chain, CA verification, validity window, and hostname matching
# ======================================================================

def validate_certificate(
    leaf_pem_path: str,
    ca_pem_path: str,
    expected_hostname: str,
) -> Certificate:
    """
    Complete PKI validation used in manual tests or config loading.
    Returns the validated leaf certificate.
    Raises a clear ValueError on any failure.
    """
    ca_cert = load_ca_certificate(ca_pem_path) #load the trusted Root CA certificate
    leaf_cert = load_certificate(leaf_pem_path) #load the leaf certificate to validate

    # 1. Chain signature - verify leaf cert is signed by CA
    if not verify_signature(ca_cert, leaf_cert):
        raise ValueError("Leaf certificate is NOT signed by the trusted CA")

    # 2. CA really is a CA - check BasicConstraints
    if not is_ca_certificate(ca_cert):
        raise ValueError("Trusted CA certificate lacks BasicConstraints ca=True")

    # 3. Validity window - check certificate is not expired
    if not check_validity(leaf_cert):
        raise ValueError(
            f"Leaf certificate outside validity window: "
            f"{leaf_cert.not_valid_before_utc} → {leaf_cert.not_valid_after_utc}"
        )

    # 4. Hostname / identity - verify CN or SAN DNS name matches expected hostname
    if not verify_identity(leaf_cert, expected_hostname):
        cn = get_common_name(leaf_cert) or "None"
        san = get_san_dns_names(leaf_cert)
        raise ValueError(
            f"Hostname mismatch – expected: {expected_hostname} | "
            f"CN: {cn} | SAN DNS: {san}"
        )

    return leaf_cert #return the validated certificate


# SECTION 3: Helpers that work with **PEM strings** (hello messages)
# Used for validating certificates received as PEM-encoded strings in the protocol (hello exchange)
# ======================================================================

def validate_server_certificate(
    server_cert_pem: str,          # PEM string from "server hello"
    ca_pem_path: str,
    expected_server_name: str,
) -> Certificate:
    """
    Client-side validation of the server certificate received in the hello.
    """
    ca_cert = load_ca_certificate(ca_pem_path) #load trusted Root CA
    cert = x509.load_pem_x509_certificate(server_cert_pem.encode("utf-8"), backend) #parse server cert from PEM string

    if not verify_signature(ca_cert, cert): #verify signature
        raise ValueError("Server certificate not signed by trusted CA")
    if not check_validity(cert): #verify not expired
        raise ValueError("Server certificate expired or not yet valid")
    if not verify_identity(cert, expected_server_name): #verify hostname matches
        raise ValueError(f"Server identity mismatch: {expected_server_name}")

    return cert #return validated server certificate


def validate_client_certificate(
    client_cert_pem: str,          # PEM string from "hello"
    ca_pem_path: str,
    expected_client_name: Optional[str] = None,
) -> Certificate:
    """
    Server-side validation of the client certificate.
    If expected_client_name is None we only check chain + validity.
    """
    ca_cert = load_ca_certificate(ca_pem_path) #load trusted Root CA
    cert = x509.load_pem_x509_certificate(client_cert_pem.encode("utf-8"), backend) #parse client cert from PEM string

    if not verify_signature(ca_cert, cert): #verify signature
        raise ValueError("Client certificate not signed by trusted CA")
    if not check_validity(cert): #verify not expired
        raise ValueError("Client certificate expired or not yet valid")
    if expected_client_name and not verify_identity(cert, expected_client_name): #verify hostname if specified
        raise ValueError(f"Client identity mismatch: {expected_client_name}")

    return cert #return validated client certificate


# SECTION 4: Simple CLI test
# Command-line interface for manual testing of certificate validation
# ======================================================================

if __name__ == "__main__":
    import sys #for command-line arguments and exit
    if len(sys.argv) != 4: #check for required arguments
        print(
            "Usage: python -m app.crypto.pki <leaf.pem> <ca.pem> <expected_hostname>"
        )
        sys.exit(1)

    leaf_path, ca_path, hostname = sys.argv[1], sys.argv[2], sys.argv[3] #parse command-line arguments
    try:
        cert = validate_certificate(leaf_path, ca_path, hostname) #validate the certificate
        print(f"Certificate VALID for {hostname}") #success message
        print(f"  Subject : {cert.subject}") #print certificate subject
        print(f"  Expires : {cert.not_valid_after_utc}") #print expiration date
    except Exception as exc:          # pragma: no cover - catch any validation error
        print(f"Validation FAILED: {exc}") #print error message

# to run this script: python -m app.crypto.pki certs/myserver.example.com_cert.pem certs/MyRootCA_ca_cert.pem myserver.example.com