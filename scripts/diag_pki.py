# Diagnostic script to inspect CA and client certificates and test signature verification
import sys
import os
# Ensure repo root is on sys.path so `import app` works when running this script directly
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.crypto.pki import (
    load_certificate, load_ca_certificate,
    get_common_name, get_san_dns_names, verify_signature, is_ca_certificate
)
import os

CLIENT_CERT = "certs/client.example.com_cert.pem"
CA_CERT = "certs/MyRootCA_ca_cert.pem"

print("Diagnostic: checking certificate files and signatures")
print("Paths:")
print(" client:", CLIENT_CERT)
print(" ca    :", CA_CERT)
print()

for p in (CLIENT_CERT, CA_CERT):
    print(f"Exists {p}:", os.path.exists(p))
    if os.path.exists(p):
        with open(p, 'r', encoding='utf-8') as f:
            d = f.read()
        starts = d.strip().startswith('-----BEGIN CERTIFICATE-----')
        print(f"  Looks like PEM cert? {starts}")
    else:
        print(f"  File missing: {p}")
print()

try:
    client = load_certificate(CLIENT_CERT)
except Exception as e:
    print("ERROR loading client cert:", e)
    raise SystemExit(1)

try:
    ca = load_ca_certificate(CA_CERT)
except Exception as e:
    print("ERROR loading CA cert:", e)
    raise SystemExit(1)

print("CA subject  :", ca.subject)
print("CA is CA?   :", is_ca_certificate(ca))
print()
print("Client subj :", client.subject)
print("Client iss  :", client.issuer)
print("Client CN   :", get_common_name(client))
print("Client SANs :", get_san_dns_names(client))
print()

ok = verify_signature(ca, client)
print("verify_signature(ca, client) ->", ok)
if not ok:
    print("Client cert is NOT signed by this CA (issuer != CA subject or signature mismatch).")
    print("Check that client cert issuer matches the CA subject above and that you used the correct CA to sign the client cert.")
else:
    print("Client cert is correctly signed by the CA.")
