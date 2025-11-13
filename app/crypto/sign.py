#"""RSA PKCS#1 v1.5 SHA-256 sign/verify.""" 
#raise NotImplementedError("students: implement RSA helpers")

# app/crypto/sign.py

# import necessary modules from the cryptography library
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


#this function signs data using RSA PKCS#1 v1.5 with SHA-256
def sign_data(private_key_pem: str, data: bytes) -> bytes:
    
    #Sign the given data using RSA PKCS#1 v1.5 with SHA-256.
    # > param private_key_pem: The private key in PEM format.
    # > param data: The data to be signed.
    # > return: The signature as bytes.

    # load the private key from PEM format
    # accept PEM as text (str) or bytes; normalize to bytes for loading
    if isinstance(private_key_pem, str):
        pem_bytes = private_key_pem.encode("utf-8")
    else:
        pem_bytes = private_key_pem

    private_key = serialization.load_pem_private_key(
        pem_bytes, password=None, backend=default_backend()
    )

    # sign the data using PKCS#1 v1.5 padding and SHA-256 hash algorithm
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return signature # return the generated signature

# this function verifies the signature of data using RSA PKCS#1 v1.5 with SHA-256
def verify_signature(public_key_pem: str, data: bytes, signature: bytes) -> bool:
    
    #Verify the signature of the given data using RSA PKCS#1 v1.5 with SHA-256.

    # > param public_key_pem: The public key in PEM format.
    # > param data: The original data that was signed.
    # > param signature: The signature to be verified.
    # > return: True if the signature is valid, False otherwise.


    # load the public key from PEM format
    # accept PEM as text (str) or bytes; normalize to bytes for loading
    if isinstance(public_key_pem, str):
        pub_bytes = public_key_pem.encode("utf-8")
    else:
        pub_bytes = public_key_pem

    public_key = serialization.load_pem_public_key(pub_bytes, backend=default_backend())

    try:
        # verify the signature using PKCS#1 v1.5 padding and SHA-256 hash algorithm
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True  # signature is valid
    except Exception:
        return False  # signature is invalid
    
######################
#` driver code for testing #
if __name__ == "__main__":
    from cryptography.hazmat.primitives.asymmetric import rsa

    # generate a new RSA key pair for testing
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # serialize keys to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # data to be signed
    data = b"Hello, this is a test message."

    # sign the data
    signature = sign_data(private_key_pem, data)
    print("Signature:", signature.hex())

    # verify the signature
    is_valid = verify_signature(public_key_pem, data, signature)
    print("Is the signature valid?", is_valid)

# end of driver code #
#######################
# cli commands to run the test:
# python app/crypto/sign.py