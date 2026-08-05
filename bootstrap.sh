#!/usr/bin/env bash
# bootstrap.sh (v2 — alur manual, tanpa AI coding agent)
# "Perancangan Profil TLS 1.3 Pasca-Kuantum Adaptif Berdasarkan Evaluasi
#  Mitigasi Overhead Sertifikat ML-DSA"
#
# Cara pakai:
#   1. Simpan file ini di root folder proyek (mis. ~/pqc-tls-profiling/bootstrap.sh)
#   2. chmod +x bootstrap.sh
#   3. ./bootstrap.sh
#   4. Salin SELURUH blok "RINGKASAN STATUS" di paling bawah output, tempel ke chat.
#
# Aman dijalankan berulang kali.

set -uo pipefail  # catatan: -e sengaja tidak dipakai supaya semua tahap tetap
                   # jalan dan dilaporkan, walau salah satu gagal (biar status akhir lengkap)

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROJECT_DIR}/.venv"

STATUS_OPENSSL_VERSION="UNKNOWN"
STATUS_MLDSA="FAIL"
STATUS_PYTHON="FAIL"
STATUS_VENV="FAIL"
STATUS_PIP_PKGS="FAIL"
STATUS_TSHARK="FAIL"
STATUS_DIRS="FAIL"

echo "== 1/6: Update paket sistem =="
sudo apt update && sudo apt upgrade -y

echo "== 2/6: Install dependency build & tools dasar =="
sudo apt install -y \
    build-essential git curl wget pkg-config libssl-dev \
    python3 python3-venv python3-pip tshark
if command -v tshark >/dev/null 2>&1; then STATUS_TSHARK="OK"; fi

echo "== 3/6: Verifikasi OpenSSL mendukung ML-DSA =="
if command -v openssl >/dev/null 2>&1; then
    STATUS_OPENSSL_VERSION="$(openssl version)"
    echo "OpenSSL terpasang: ${STATUS_OPENSSL_VERSION}"
    if openssl list -signature-algorithms 2>/dev/null | grep -qi "ML-DSA"; then
        STATUS_MLDSA="OK"
        echo "OK: ML-DSA terdeteksi."
    else
        echo "PERINGATAN: ML-DSA tidak terdeteksi. Cek 'which openssl' — WSL kadang"
        echo "punya openssl bawaan distro yang lebih lama di /usr/bin selain openssl 3.5.x Anda."
    fi
else
    echo "PERINGATAN: openssl tidak ditemukan di PATH."
fi

echo "== 4/6: Buat virtual environment Python =="
if command -v python3 >/dev/null 2>&1; then
    STATUS_PYTHON="OK ($(python3 --version 2>&1))"
    if [ ! -d "${VENV_DIR}" ]; then
        python3 -m venv "${VENV_DIR}"
    fi
    if [ -d "${VENV_DIR}" ]; then
        STATUS_VENV="OK"
        # shellcheck source=/dev/null
        source "${VENV_DIR}/bin/activate"
    fi
fi

echo "== 5/6: Install dependency Python =="
if [ "${STATUS_VENV}" = "OK" ]; then
    pip install --upgrade pip
    pip install cryptography asn1crypto psutil scapy pandas matplotlib pytest

    FAILED_PKGS=""
    for pkg in cryptography asn1crypto psutil scapy pandas matplotlib pytest; do
        python3 -c "import ${pkg}" 2>/dev/null || FAILED_PKGS="${FAILED_PKGS} ${pkg}"
    done
    if [ -z "${FAILED_PKGS}" ]; then
        STATUS_PIP_PKGS="OK (semua 7 package bisa di-import)"
    else
        STATUS_PIP_PKGS="SEBAGIAN GAGAL:${FAILED_PKGS}"
    fi
fi

echo "== 6/6: Siapkan struktur direktori proyek =="
mkdir -p pki/{mldsa44,mldsa65,mldsa87,ecc-p256,ecc-p384,ecc-p521}
mkdir -p src/common data/raw docs notebooks
if [ -d pki/mldsa44 ] && [ -d src/common ] && [ -d data/raw ]; then
    STATUS_DIRS="OK"
fi

cat > requirements.txt <<'EOF'
cryptography
asn1crypto
psutil
scapy
pandas
matplotlib
pytest
EOF

echo ""
echo "=================== RINGKASAN STATUS ==================="
echo "OpenSSL version     : ${STATUS_OPENSSL_VERSION}"
echo "OpenSSL ML-DSA       : ${STATUS_MLDSA}"
echo "Python3              : ${STATUS_PYTHON}"
echo "Virtualenv (.venv)   : ${STATUS_VENV}"
echo "Python packages      : ${STATUS_PIP_PKGS}"
echo "tshark                : ${STATUS_TSHARK}"
echo "Struktur direktori   : ${STATUS_DIRS}"
echo "=========================================================="
echo "-> Salin blok RINGKASAN STATUS di atas (7 baris), tempel ke chat."
echo "-> Aktifkan environment tiap sesi baru dengan: source .venv/bin/activate"
