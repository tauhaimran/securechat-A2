"""Client skeleton — plain TCP; no TLS. See assignment spec."""

# def main():
#     raise NotImplementedError("students: implement client workflow")

# if __name__ == "__main__":
#     main()

from app.crypto.pki import validate_server_certificate

# ca.pem is bundled with your client
CA_PATH = "certs/MyRootCA_ca_cert.pem"
EXPECTED_SERVER = "myserver.example.com"

server_cert = validate_server_certificate(
    server_hello_msg["server cert"],
    CA_PATH,
    EXPECTED_SERVER
)