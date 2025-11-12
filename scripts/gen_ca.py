#"""Create Root CA (RSA + self-signed X.509) using cryptography.""" 
#raise NotImplementedError("students: implement CA generation")

#PURPOSE: Create a Root Certificate Authority (CA) that can later sign other certificates (client & server)

#these are reequired imports for this assignment
import argparse
from datetime import datetime, timedelta #for setting certificate validity period
from cryptography import x509 #for X.509 certificate creation
from cryptography.x509.oid import NameOID #for X.509 Name OIDs
from cryptography.hazmat.primitives import hashes, serialization #for serialization
from cryptography.hazmat.primitives.asymmetric import rsa #for RSA key generation
from cryptography.hazmat.backends import default_backend #for default backend
import os #for file operations

def create_root_ca( ca_name: str , output_dir: str = "certs"):

    #making a /certs directory if it does not exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 1. Generate RSA Private Key for the CA
    rsa_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 2. build X.509 Subject/Issuer Name ( self-signed, so subject == issuer )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"), #Pakistan
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"ICT"), #Islamabad Capital Territory
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"), #City
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NU"), #Organization
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
    ])

    # 3. Create self-signed X.509 Certificate
    certificate = (
        x509.CertificateBuilder() # start building certificate
        .subject_name(subject) # same as issuer for self-signed
        .issuer_name(issuer) # self-signed
        .public_key(rsa_private_key.public_key()) # public key
        .serial_number(x509.random_serial_number()) # random serial number
        .not_valid_before(datetime.utcnow()) # valid from now
        .not_valid_after(datetime.utcnow() + timedelta(days=1825))  # ~5 years 
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) # CA: TRUE
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(rsa_private_key.public_key()), critical=False) # Subject Key Identifier
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(rsa_private_key.public_key()), critical=False) # Authority Key Identifier
        .sign(private_key=rsa_private_key, algorithm=hashes.SHA256(), backend=default_backend()) # sign with private key
    ) 

    # 4. Write Private Key to PEM (Privacy-Enhanced Mail) file
    key_path = os.path.join(output_dir, f"{ca_name}_ca_key.pem")
    with open(key_path, "wb") as key_file: # write binary mode
        key_file.write( # write private key in PEM format
            rsa_private_key.private_bytes( # serialize private key
                encoding=serialization.Encoding.PEM, # PEM encoding ( Privacy-Enhanced Mail )
                format=serialization.PrivateFormat.TraditionalOpenSSL, # traditional OpenSSL format ( this does not violate assignment rules , it is just a format )
                encryption_algorithm=serialization.NoEncryption() # no encryption for simplicity
            )
        )
    
    # 5. Write Certificate to PEM file
    cert_path = os.path.join(output_dir, f"{ca_name}_ca_cert.pem")
    with open(cert_path, "wb") as cert_file: # write binary mode
        cert_file.write(
            certificate.public_bytes(serialization.Encoding.PEM)
        )
    
    # Print success message with file paths
    print(f"Root CA generated successfully!")
    print(f"Private Key: {key_path}")
    print(f"Certificate: {cert_path}")


############################
# DRIVER CODE - COMMENT THIS OUT WHEN TESTING FULL APP
############################
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a Root CA (RSA + self-signed X.509 Certificate).")
    parser.add_argument("--ca-name", type=str, required=True, help="Common Name for the CA (e.g., 'MyRootCA').")
    parser.add_argument("--output-dir", type=str, default="certs", help="Directory to save the generated CA files.")
    args = parser.parse_args()

    create_root_ca(ca_name=args.ca_name, output_dir=args.output_dir)
    
############################
# to run from command line:
# python scripts/gen_ca.py --ca-name MyRootCA --output-dir certs
