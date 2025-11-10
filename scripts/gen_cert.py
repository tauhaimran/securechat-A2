#"""Issue server/client cert signed by Root CA (SAN=DNSName(CN)).""" 
#raise NotImplementedError("students: implement cert issuance")

#
#Issue server/client certificate signed by Root CA (SAN=DNSName(CN)).
#mplements assignment requirement for certificate issuance.
#Adapted from cryptography.io X.509 examples.


#these are required imports for this file in the assignment
import argparse #for command-line argument parsing
import os #for file operations
from datetime import datetime, timedelta #for setting certificate validity period
from cryptography import x509 #for X.509 certificate creation
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID #for X.509 Name OIDs and Extended Key Usage OIDs
from cryptography.hazmat.primitives import hashes, serialization #`for serialization
from cryptography.hazmat.primitives.asymmetric import rsa #for RSA key generation
from cryptography.hazmat.backends import default_backend #for default backend


def issue_certificate(ca_name: str, cert_name: str, cert_type: str, output_dir: str = "certs"):
    #making a /certs directory if it does not exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 1 Load CA Private Key and certificate
    ca_key_path = os.path.join(output_dir, f"{ca_name}_ca_key.pem")
    ca_cert_path = os.path.join(output_dir, f"{ca_name}_ca_cert.pem")

    # Check if CA files exist
    if not os.path.exists(ca_key_path) or not os.path.exists(ca_cert_path):
        raise FileNotFoundError("CA key or certificate file not found. Please generate the CA first.")
    
    # Load CA Private Key
    with open(ca_key_path, "rb") as key_file: # read CA key
        ca_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    
    # Load CA Certificate
    with open(ca_cert_path, "rb") as cert_file: # read CA cert
        ca_certificate = x509.load_pem_x509_certificate(
            cert_file.read(), 
            backend=default_backend()
        )
    
    # 2 Generate RSA Private Key for this entity (server/client)
    entity_rsa_private_key = rsa.generate_private_key(
        public_exponent=65537, # common public exponent
        key_size=2048, #2048 bits for security
        backend=default_backend() # default backend
    )

    # 3 Build X.509 certificate subject ( different from issuer which is CA )
    subject = x509.Name([ # subject name attributes
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "ICT"), # Islamabad Capital Territory
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"), # City
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Entity"), # Organization
        x509.NameAttribute(NameOID.COMMON_NAME, cert_name), # Common Name
    ])

    # 4 build and sign the X.509 certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject) # subject name
        .issuer_name(ca_certificate.subject) # issuer name from CA cert
        .public_key(entity_rsa_private_key.public_key()) # entity public key
        .serial_number(x509.random_serial_number()) # random serial number
        .not_valid_before(datetime.utcnow()) # valid from now
        .not_valid_after(datetime.utcnow() + timedelta(days=825))  # ~2.25 years 
        .add_extension( # SAN with DNSName
            x509.SubjectAlternativeName([x509.DNSName(cert_name)]), # SAN extension ( Subject Alternative Name )
            critical=False # not critical
        )
        .add_extension( # Key Usage extension
            x509.KeyUsage( # Key Usage extension via x509.KeyUsage class
                digital_signature=True, #  digital signature - used for signatures
                key_encipherment=True, # key encipherment - used for TLS ( Transport Layer Security )
                key_cert_sign=False, # key cert sign - not used
                crl_sign=False, # crl sign - not used
                content_commitment=True, # content commitment - used for non-repudiation
                data_encipherment=False, # data encipherment - not used
                #this one was causing an error cause The error with KeyUsage is because I missed the required argument key_agreement in the x509.KeyUsage constructor.
                #To fix the TypeError, I had to add key_agreement=False to the x509.KeyUsage call.
                key_agreement=False, # key agreement - not used <- error fixed by adding this line
                encipher_only=False, # encipher only - not used
                decipher_only=False, # decipher only - not used
            ),
            critical=True
        )
        .add_extension( # Extended Key Usage extension
            x509.ExtendedKeyUsage([ # Extended Key Usage extension via x509.ExtendedKeyUsage class
                ExtendedKeyUsageOID.SERVER_AUTH if cert_type == "server" else ExtendedKeyUsageOID.CLIENT_AUTH # server auth or client auth
            ]),
            critical=False # not critical
        ) 
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()), critical=False) # Authority Key Identifier
    )

    # sign cert with CA private key
    cert = cert_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())

    # 5 Write entity Private Key to files
    entity_key_path = os.path.join(output_dir, f"{cert_name}_key.pem")
    entit_cert_path = os.path.join(output_dir, f"{cert_name}_cert.pem")

    # Write entity Certificate to PEM file
    with open(entity_key_path, "wb") as key_file: # write binary mode
        key_file.write( # write private key in PEM format
            entity_rsa_private_key.private_bytes( # serialize private key
                encoding=serialization.Encoding.PEM, # PEM encoding ( Privacy-Enhanced Mail )
                format=serialization.PrivateFormat.TraditionalOpenSSL, # traditional OpenSSL format
                encryption_algorithm=serialization.NoEncryption() # no encryption for simplicity
            )
        )
    # Write Certificate to PEM file
    with open(entit_cert_path, "wb") as cert_file: # write binary mode
        cert_file.write(
            cert.public_bytes(serialization.Encoding.PEM)
        )

    # Print success message with file paths
    print(f"{cert_type.capitalize()} certificate issued successfully!")
    print(f"Private Key: {entity_key_path}")
    print(f"Certificate: {entit_cert_path}")


############################
# DRIVER CODE - COMMENT THIS OUT WHEN TESTING FULL APP
############################
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Issue server/client certificate signed by Root CA.")
    parser.add_argument("ca_name", type=str, help="Name of the Root CA (used in file names).")
    parser.add_argument("cert_name", type=str, help="Common Name (CN) for the new certificate.")
    parser.add_argument("cert_type", type=str, choices=["server", "client"], help="Type of certificate to issue (server/client).")
    parser.add_argument("--output_dir", type=str, default="certs", help="Directory to save the issued certificate and key.")
    
    args = parser.parse_args()
    
    issue_certificate(args.ca_name, args.cert_name, args.cert_type, args.output_dir)

############################
# End of DRIVER CODE
############################
# to run from command line:
# python scripts/gen_cert.py MyRootCA myserver.example.com server --output_dir certs
