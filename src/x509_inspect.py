#!/usr/bin/env python3
"""
x509_inspect.py — Bedah struktur X.509 tiap sertifikat, ukur byte tiap komponen.

Mekanisme (WAJIB CUSTOM per PRD Bagian 4 — bukan `openssl x509 -text`):
- Certificate (RFC 5280) adalah SEQUENCE tiga field top-level:
    Certificate  ::=  SEQUENCE {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING }
- TBSCertificate sendiri berisi (antara lain) SubjectPublicKeyInfo dan
  Extensions, yang menjadi kontributor utama overhead ML-DSA vs ECC.
- Kita memakai `asn1crypto` HANYA sebagai library ASN.1 tingkat rendah untuk
  membongkar tag/length/value; keputusan field mana yang diukur, dan logika
  penghitungan ukuran tiap komponen, ditulis sendiri di bawah.
- Tidak ada pemanggilan `openssl` di skrip ini — PEM->DER dan traversal
  struktur 100% dilakukan di Python.
"""

import csv
import sys
from pathlib import Path

from asn1crypto import pem, x509

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PKI_DIR = PROJECT_ROOT / "pki"

ALGORITHM_LEVELS = [
    (algo, level)
    for algo in ["mldsa44", "mldsa65", "mldsa87", "ecc-p256", "ecc-p384", "ecc-p521"]
    for level in ["root", "intermediate", "leaf"]
]


def load_der(cert_path: Path) -> bytes:
    """Baca file .crt (PEM) dan kembalikan DER mentahnya (tanpa openssl)."""
    raw = cert_path.read_bytes()
    _, _, der_bytes = pem.unarmor(raw)
    return der_bytes


def inspect_certificate(der_bytes: bytes) -> dict:
    """
    Bongkar Certificate menjadi 5 komponen wajib (PRD Bagian 4) dan hitung
    ukuran DER masing-masing dalam byte.
    .dump() pada tiap child asn1crypto mengembalikan encoding DER LENGKAP
    komponen itu (tag + length + value), bukan cuma isinya — ini yang benar
    untuk "ukuran komponen" pada level wire format TLS.
    """
    cert = x509.Certificate.load(der_bytes)
    tbs = cert["tbs_certificate"]
    sig_algo = cert["signature_algorithm"]
    sig_value = cert["signature_value"]
    spki = tbs["subject_public_key_info"]
    extensions = tbs["extensions"]

    tbs_bytes = len(tbs.dump())
    sig_algo_bytes = len(sig_algo.dump())
    sig_value_bytes = len(sig_value.dump())
    spki_bytes = len(spki.dump())

    # extensions bisa VOID (tidak ada) pada beberapa cert; asn1crypto
    # merepresentasikan field opsional yang kosong sebagai None.
    extensions_bytes = len(extensions.dump()) if extensions.native is not None else 0
    total_bytes = len(der_bytes)

    return {
        "total_bytes": total_bytes,
        "tbs_certificate_bytes": tbs_bytes,
        "signature_algorithm_bytes": sig_algo_bytes,
        "signature_value_bytes": sig_value_bytes,
        "subject_public_key_info_bytes": spki_bytes,
        "extensions_bytes": extensions_bytes,
        # Field identitas, bukan hasil pengukuran ukuran:
        "signature_algorithm_name": sig_algo["algorithm"].native,
        "subject": tbs["subject"].human_friendly,
        "issuer": tbs["issuer"].human_friendly,
    }


def inspect_all() -> list[dict]:
    rows = []
    for algo, level in ALGORITHM_LEVELS:
        cert_path = PKI_DIR / algo / f"{level}.crt"
        if not cert_path.exists():
            print(f"SKIP (tidak ditemukan): {cert_path}", file=sys.stderr)
            continue

        der_bytes = load_der(cert_path)
        metrics = inspect_certificate(der_bytes)
        row = {
            "algorithm_code": algo,
            "cert_level": level,
            **metrics,
        }
        rows.append(row)

        print(f"\n=== {algo} / {level} ===")
        print(f"  Signature algorithm     : {metrics['signature_algorithm_name']}")
        print(f"  Subject                 : {metrics['subject']}")
        print(f"  Issuer                  : {metrics['issuer']}")
        print(f"  Total cert (DER)        : {metrics['total_bytes']} bytes")
        print(f"  TBSCertificate          : {metrics['tbs_certificate_bytes']} bytes")
        print(f"  AlgorithmIdentifier     : {metrics['signature_algorithm_bytes']} bytes")
        print(f"  SubjectPublicKeyInfo    : {metrics['subject_public_key_info_bytes']} bytes")
        print(f"  Extensions              : {metrics['extensions_bytes']} bytes")
        print(f"  SignatureValue          : {metrics['signature_value_bytes']} bytes")
    return rows


def write_csv(rows: list[dict], out_path: Path) -> None:
    if not rows:
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nDitulis: {out_path} ({len(rows)} baris)")


def main() -> None:
    rows = inspect_all()
    write_csv(rows, PROJECT_ROOT / "data" / "raw" / "x509_component_sizes.csv")


if __name__ == "__main__":
    main()
