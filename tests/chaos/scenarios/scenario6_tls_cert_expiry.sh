#!/bin/sh
# R8 scenario 6 — TLS cert expiry.
#
# Configure mTLS with a cert that expires in 60s; run a consumer
# loop for 90s; observe the post-expiry error. Daemon must not
# crash.
#
# DEFERRED to a future round if mTLS fixture isn't set up — this
# script lays out the procedure but the full automation needs:
#   - script to mint a short-lived CA + server + client cert
#   - chaos-daemon image variant with TLS configured
#   - consumer-shell with the corresponding client cert mounted

set -u
. "$(dirname "$0")/_common.sh"

echo "=== R8 scenario 6: TLS cert expiry (DEFERRED) ==="
echo "  This scenario is documented but not yet automated; full"
echo "  fixture requires:"
echo "    1. mint CA + server cert (notAfter = now + 60s) + client cert"
echo "    2. start chaos-daemon with mTLS pointing at the certs"
echo "    3. consumer-shell with client cert, sign loop for 90s"
echo "    4. observe the CK_RV returned after t=60s"
echo
echo "  Tracked as R8-FOLLOWUP-tls-cert-expiry-automation."
echo "scenario6: DEFER (documented, not automated)"
exit 0
