"""Server skeleton — plain TCP; no TLS. See assignment spec."""

# def main():
#     raise NotImplementedError("students: implement server workflow")

# if __name__ == "__main__":
#     main()

from app.crypto.pki import validate_client_certificate

CA_PATH = "certs/MyRootCA_ca_cert.pem"

client_cert = validate_client_certificate(
    client_hello_msg["client cert"],
    CA_PATH
    # Optionally pass expected CN if you enforce it
)