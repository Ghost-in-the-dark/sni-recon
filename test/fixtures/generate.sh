#!/usr/bin/env bash
# Generate the self-signed certificate fixture used by the test suite and selftest.
#
# The key is deliberately NOT committed: a private key in a repository trips secret
# scanners and normalises a bad habit. It is a throwaway test key with no trust value.
set -euo pipefail
cd "$(dirname "$0")"

if [ -f selfsigned.pem ] && [ -f key.pem ]; then
  echo "fixtures already present"
  exit 0
fi

openssl req -x509 -newkey rsa:2048 \
  -keyout key.pem -out selfsigned.pem \
  -days 3650 -nodes \
  -subj "/C=XX/O=sni-recon self test/CN=self-test.invalid" \
  -addext "subjectAltName=DNS:self-test.invalid,DNS:*.self-test.invalid" \
  2>/dev/null

chmod 600 key.pem
echo "generated test/fixtures/selfsigned.pem and key.pem"
