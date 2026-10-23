#!/usr/bin/env bash
# Scaffold for the emsign-bundle eval case: a Python updater that downloads
# plugin archives over TLS with a vendored CA bundle that still lists emSign
# roots, built on an image that pins pip 26.2.1. It holds no secrets.
# The PEM bodies are random placeholder data, not real certificates, and the
# download host is under .example.invalid.
set -euo pipefail

# Write only into the eval run's empty workspace. Refuse anywhere else.
if [ "$PWD" = "/" ] || [ -n "$(ls -A .)" ]; then
  echo "refusing to scaffold: run this from an empty eval workspace" >&2
  exit 1
fi

mkdir -p certs updater

cat > Dockerfile <<'EOF'
FROM python:3.12-slim
WORKDIR /srv
RUN pip install --no-cache-dir pip==26.2.1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY certs/ certs/
COPY updater/ updater/
CMD ["python", "-m", "updater.fetch"]
EOF

cat > requirements.txt <<'EOF'
requests==2.32.5
EOF

cat > updater/__init__.py <<'EOF'
EOF

cat > updater/fetch.py <<'EOF'
import hashlib
import os
import zipfile
from pathlib import Path

import requests

CA_BUNDLE = Path(__file__).resolve().parent.parent / "certs" / "cacert.pem"
INDEX_URL = "https://plugins.example.invalid/index.json"
PLUGIN_DIR = Path(os.environ.get("PLUGIN_DIR", "/srv/plugins"))


def fetch(url):
    resp = requests.get(url, verify=str(CA_BUNDLE), timeout=30)
    resp.raise_for_status()
    return resp


def main():
    index = fetch(INDEX_URL).json()
    PLUGIN_DIR.mkdir(parents=True, exist_ok=True)
    for item in index["plugins"]:
        blob = fetch(item["url"]).content
        if hashlib.sha256(blob).hexdigest() != item["sha256"]:
            raise SystemExit(f"checksum mismatch for {item['name']}")
        target = PLUGIN_DIR / f"{item['name']}.zip"
        target.write_bytes(blob)
        with zipfile.ZipFile(target) as zf:
            zf.extractall(PLUGIN_DIR / item["name"])


if __name__ == "__main__":
    main()
EOF

cat > certs/cacert.pem <<'EOF'
##
## Bundle of CA Root Certificates
##
## Vendored copy, last refreshed 2025-11-02.
##

# Issuer: CN=ISRG Root X1 O=Internet Security Research Group
# Subject: CN=ISRG Root X1 O=Internet Security Research Group
# Label: "ISRG Root X1"
-----BEGIN CERTIFICATE-----
MIIFwionDFNJrCBBYjhKSlQDF2CvjVsW4/Nfk9o95KaRjOBiXxp2yHsXM0iwNAyB
OPfaR/Ej7+9aLZ5n9buYSuAkYhkNSglcCMv2AyF3SEMRqMP2/mAJvXcGob2D7/Uv
mXImCtciWznGF1eXd8ECPxcE2R+QJR49Q8E5rx5xUDGR59tMCsx/9o49EcKjCL7i
C33ULviQCADBHwi3Z9D5xamhyQmE/En16R7X2xDG2k2sMDyNzOXwMwMvoC485B/M
77AwLC0/NZ1XaQ5gZK7XHUfaF6H6GFrI+ZfVehwLaMNwppj9Q67EB7dRmHKnVIdd
-----END CERTIFICATE-----

# Issuer: CN=emSign Root CA - G1 O=eMudhra Technologies Limited OU=emSign PKI
# Subject: CN=emSign Root CA - G1 O=eMudhra Technologies Limited OU=emSign PKI
# Label: "emSign Root CA - G1"
-----BEGIN CERTIFICATE-----
MIIDtOnrYUiz8cUjrmHsSq8Nt7gAAPyqDTgPUZOpX1ikJNQ3SgIicsVXsRN7KYum
k1nfbt0J7f8z6ZdZgHBUoWZF9DLfpfGvxoz+X2oXVxpBjijpr1IAJf8s2VqS6Q7S
DIFS//oAefhghI8JI5ioYPYri6i7gQ6QE6L2b+jH7YeqDziJiIpfNG0xNjXXI7yd
okccyBetnGi+E4R2EmMzECoPTlSMTu7AFtYd2WL9vKM9dzyEW+zdUnbFKD1AmfFf
-----END CERTIFICATE-----

# Issuer: CN=emSign ECC Root CA - G3 O=eMudhra Technologies Limited OU=emSign PKI
# Subject: CN=emSign ECC Root CA - G3 O=eMudhra Technologies Limited OU=emSign PKI
# Label: "emSign ECC Root CA - G3"
-----BEGIN CERTIFICATE-----
MIICScS4y2J1l3t2PFDi/dzRZ7UauwYIYSEWZGR/EDL+dVBIuftCvYNXg33gm5RQ
bpa//rjqEZbKPtaUcjgXfCUY6B2xI1xs1MceJoRBIwhJEII7eD8yUrmj1R0qQ9B2
U+9Vh5PWEXBX01X8BuVADs9Jj1f7m93xfJMYYG6Zd1F0Tb0OhuPmcqxgYKk6z+xG
-----END CERTIFICATE-----
EOF

cat > README.md <<'EOF'
# plugin-updater

Downloads plugin archives listed in the index and unpacks them. Uses the vendored CA
bundle in `certs/` so the container does not depend on the base image's trust store.
EOF
