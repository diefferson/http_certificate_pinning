#!/usr/bin/env bash
#
# Prints the public key pins (base64-encoded SHA-256 of the SubjectPublicKeyInfo)
# for every certificate in the TLS chain a server presents. The values can be fed
# directly to HttpCertificatePinning.checkPublicKeys / checkLeaf /
# checkIntermediate / checkRoot.
#
# Positions follow the plugin's chain semantics: the first certificate is the
# leaf, the second is the intermediate (only in chains of 3+), and the last one
# is the root. Servers usually omit the actual root CA; the last certificate
# sent is labeled root regardless, as that is what the Android implementation
# compares against (iOS resolves the root from the system trust store).
#
# Usage: ./get_public_key_pins.sh <host> [port]

set -euo pipefail

host="${1:?Usage: $0 <host> [port]}"
port="${2:-443}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

if ! openssl s_client -connect "${host}:${port}" -servername "${host}" -showcerts \
    </dev/null 2>/dev/null >"${tmpdir}/chain.txt"; then
  echo "error: could not connect to ${host}:${port}" >&2
  exit 1
fi

awk -v dir="$tmpdir" '
  /-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/cert%02d.pem", dir, n) }
  f { print > f }
  /-----END CERTIFICATE-----/ { f = "" }
' "${tmpdir}/chain.txt"

certs=("${tmpdir}"/cert*.pem)
count="${#certs[@]}"

if [ "$count" -eq 0 ] || [ ! -e "${certs[0]}" ]; then
  echo "error: no certificates received from ${host}:${port}" >&2
  exit 1
fi

echo "Certificate chain for ${host}:${port} (${count} certificate(s), leaf first):"
echo

index=0
for cert in "${certs[@]}"; do
  index=$((index + 1))

  position=""
  if [ "$index" -eq 1 ]; then
    position="leaf"
  fi
  if [ "$index" -eq 2 ] && [ "$count" -gt 2 ]; then
    position="intermediate"
  fi
  if [ "$index" -eq "$count" ] && [ "$count" -gt 1 ]; then
    position="${position:+${position}, }root"
  fi
  position="${position:-(unpinned position)}"

  subject="$(openssl x509 -in "$cert" -noout -subject | sed 's/^subject= *//')"
  pin="$(openssl x509 -in "$cert" -pubkey -noout \
      | openssl pkey -pubin -outform der 2>/dev/null \
      | openssl dgst -sha256 -binary \
      | base64)"

  printf '[%s]\n' "$position"
  printf '  subject: %s\n' "$subject"
  printf '  pin:     %s\n' "$pin"
  echo
done
