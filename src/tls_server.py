#!/usr/bin/env python3
"""
tls_server.py — Jalankan server TLS 1.3 nyata (openssl s_server) untuk satu
hierarki algoritma tertentu (FR-5, FR-6, FR-7).

Mekanisme:
- Engine handshake TLS memakai `openssl s_server` (primitif yang diizinkan
  PRD Bagian 4 — kita TIDAK mengimplementasikan ulang protokol TLS).
- PENTING (bug yang diperbaiki di versi ini): leaf certificate WAJIB lewat
  `-cert`, dan cert tambahan yang ingin dikirim sebagai chain (intermediate,
  root) WAJIB lewat `-cert_chain <file>` terpisah. Menaruh leaf+intermediate
  +root sekaligus dalam satu file lalu memberikannya ke `-cert` TIDAK
  membuat OpenSSL 3.5 mengirim semuanya sebagai chain — hanya cert pertama
  yang dianggap leaf, sisanya diabaikan begitu saja (menyebabkan client
  gagal verifikasi rantai walau sertifikatnya sendiri valid).
- Rantai yang dikirim ke client dikontrol lewat isi file `-cert_chain`,
  dipakai nanti untuk mitigasi "chain pruning" (Bagian 5 & FR-7):
    - full     : kirim intermediate + root tambahan (chain_length=3)
    - no-root  : kirim intermediate saja            (chain_length=2)
    - leaf-only: tidak ada -cert_chain sama sekali   (chain_length=1)
- Session resumption (PSK-based, RFC 8446 NewSessionTicket) aktif secara
  default di openssl s_server TLS 1.3. --no-ticket menonaktifkannya untuk
  perbandingan (FR-6, dipakai modul mitigasi terpisah nanti).
"""

import argparse
import os
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PKI_DIR = PROJECT_ROOT / "pki"
TMP_DIR = PROJECT_ROOT / "data" / "raw" / "tls_tmp"

PORTS = {
    "mldsa44": 8443,
    "mldsa65": 8444,
    "mldsa87": 8445,
    "ecc-p256": 8446,
    "ecc-p384": 8447,
    "ecc-p521": 8448,
}

# Level TAMBAHAN (di luar leaf) yang dikirim lewat -cert_chain, per mode.
EXTRA_CHAIN_LEVELS = {
    "full": ["intermediate", "root"],
    "no-root": ["intermediate"],
    "leaf-only": [],
}


def build_cert_chain_file(algo: str, chain_mode: str) -> Path | None:
    """
    Gabungkan cert TAMBAHAN (bukan leaf) sesuai chain_mode jadi satu file
    PEM untuk -cert_chain. Return None kalau tidak ada cert tambahan
    (chain_mode == leaf-only), supaya -cert_chain tidak usah dipakai sama
    sekali dan server benar-benar hanya mengirim leaf.
    """
    levels = EXTRA_CHAIN_LEVELS[chain_mode]
    if not levels:
        return None
    out_dir = TMP_DIR / algo
    out_dir.mkdir(parents=True, exist_ok=True)
    chain_path = out_dir / f"cert_chain_{chain_mode}.pem"
    combined = ""
    for level in levels:
        cert_file = PKI_DIR / algo / f"{level}.crt"
        if not cert_file.exists():
            raise SystemExit(
                f"FATAL: {cert_file} tidak ditemukan. Jalankan gen_pki.py dulu."
            )
        combined += cert_file.read_text()
    chain_path.write_text(combined)
    return chain_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--algo", required=True, choices=sorted(PORTS.keys()))
    parser.add_argument(
        "--chain-mode",
        default="full",
        choices=sorted(EXTRA_CHAIN_LEVELS.keys()),
    )
    parser.add_argument(
        "--no-ticket",
        action="store_true",
        help="Nonaktifkan session ticket (mitigasi resumption OFF)",
    )
    parser.add_argument(
        "--naccept",
        type=int,
        default=None,
        help="Batasi jumlah koneksi lalu server berhenti sendiri",
    )
    args = parser.parse_args()

    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit(
            "FATAL: openssl tidak ditemukan di PATH. Jalankan source env.sh dulu."
        )

    port = PORTS[args.algo]
    leaf_crt = PKI_DIR / args.algo / "leaf.crt"
    leaf_key = PKI_DIR / args.algo / "leaf.key"
    if not leaf_crt.exists() or not leaf_key.exists():
        raise SystemExit(
            f"FATAL: {leaf_crt} / {leaf_key} tidak ditemukan. Jalankan gen_pki.py dulu."
        )

    cert_chain_file = build_cert_chain_file(args.algo, args.chain_mode)
    chain_length = 1 + len(EXTRA_CHAIN_LEVELS[args.chain_mode])

    cmd = [
        openssl,
        "s_server",
        "-accept",
        str(port),
        "-tls1_3",
        "-cert",
        str(leaf_crt),
        "-key",
        str(leaf_key),
        "-www",
        "-quiet",
    ]

    if cert_chain_file is not None:
        cmd += ["-cert_chain", str(cert_chain_file)]
    if args.no_ticket:
        cmd.append("-no_ticket")
    if args.naccept is not None:
        cmd += ["-naccept", str(args.naccept)]

    print(f"=== TLS 1.3 server: {args.algo} ===", file=sys.stderr)
    print(f"Port           : {port}", file=sys.stderr)
    print(
        f"Chain mode     : {args.chain_mode} (chain_length={chain_length})",
        file=sys.stderr,
    )
    print(
        f"Session ticket : {'OFF' if args.no_ticket else 'ON (default)'}",
        file=sys.stderr,
    )
    print(f"Leaf cert      : {leaf_crt}", file=sys.stderr)
    print(f"Cert chain file: {cert_chain_file}", file=sys.stderr)
    print(
        f"Uji manual     : openssl s_client -connect localhost:{port} -tls1_3 -CAfile {PKI_DIR / args.algo / 'root.crt'}",
        file=sys.stderr,
    )
    print(f"$ {' '.join(cmd)}", file=sys.stderr)

    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()
