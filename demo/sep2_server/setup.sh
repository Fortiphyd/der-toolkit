#!/usr/bin/env bash
# One-time setup for the SEP2 demo server: generates a fresh test PKI, then
# patches the registered client's LFDI into both demo configs.
#
# The registered LFDI is a hash of client_registered.crt's actual key
# material, which gen_certs.sh regenerates randomly every run -- it can't be
# hardcoded in the committed configs, so this script computes it fresh and
# substitutes it in place of REGISTERED_LFDI_PLACEHOLDER.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

./gen_certs.sh

LFDI=$(python3 -c "
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
with open('certs/client_registered.crt', 'rb') as f:
    cert = x509.load_pem_x509_certificate(f.read())
print(hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()[:40].upper())
")

echo ""
echo "Registered client LFDI: $LFDI"

for cfg in configs/hardened.yaml configs/vulnerable.yaml; do
    # Matches the placeholder on a first run, or a previously-patched LFDI on
    # a re-run (gen_certs.sh regenerates certs -- and thus the LFDI -- every
    # time), so running this script twice stays correct rather than stale.
    python3 - "$cfg" "$LFDI" <<'PYEOF'
import re, sys
path, lfdi = sys.argv[1], sys.argv[2]
text = open(path).read()
text = re.sub(r'(registered_lfdis:\s*\n\s*- ")[^"]*(")', rf'\g<1>{lfdi}\g<2>', text)
open(path, "w").write(text)
PYEOF
    echo "  patched into $cfg"
done

echo ""
echo "Setup complete. Start a server with:"
echo "  python3 server.py --config configs/hardened.yaml"
echo "  python3 server.py --config configs/vulnerable.yaml"
