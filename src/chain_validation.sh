#!/usr/bin/env bash
set -euo pipefail

# Daftar algoritma hierarki PKI
ALGORITHMS=(
    "mldsa44"
    "mldsa65"
    "mldsa87"
    "ecc-p256"
    "ecc-p384"
    "ecc-p521"
)

echo "=========================================="
echo "   VERIFIKASI RANTAI SERTIFIKAT (PKI)    "
echo "=========================================="

for algo in "${ALGORITHMS[@]}"; do
    echo -e "\n=== Algoritma: ${algo} ==="
    openssl verify \
        -CAfile "pki/${algo}/root.crt" \
        -untrusted "pki/${algo}/intermediate.crt" \
        "pki/${algo}/leaf.crt"
done

echo -e "\n------------------------------------------"
echo "Verifikasi seluruh rantai PKI selesai."
