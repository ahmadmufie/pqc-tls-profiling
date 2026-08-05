#!/usr/bin/env python3
"""
gen_pki.py — Generate 6 hierarki PKI homogen (root -> intermediate -> leaf).

Mekanisme:
- Tiap hierarki memakai SATU algoritma tanda tangan di semua level (homogen).
- Root: self-signed CA (subject == issuer), basicConstraints CA:TRUE pathlen:1.
- Intermediate: CSR ditandatangani oleh root. WAJIB basicConstraints CA:TRUE
  pathlen:0 (boleh menandatangani leaf, tidak boleh menandatangani CA lain).
- Leaf: CSR ditandatangani oleh intermediate. basicConstraints CA:FALSE, plus
  subjectAltName (wajib untuk trust hostname modern, RFC 6125 / Chrome 58+).
- Operasi kriptografi primitif (keygen, self-sign, CA-sign) memakai binary
  `openssl` CLI via subprocess — primitif yang diizinkan PRD Bagian 4,
  BUKAN implementasi ulang matematika ML-DSA/ECDSA.
- Skrip ini TIDAK melakukan verifikasi/parsing manual byte-level; itu adalah
  tanggung jawab x509_inspect.py (tugas terpisah).
"""

import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PKI_DIR = PROJECT_ROOT / "pki"

ALGORITHMS = {
    "mldsa44": ("ML-DSA-44", "mldsa"),
    "mldsa65": ("ML-DSA-65", "mldsa"),
    "mldsa87": ("ML-DSA-87", "mldsa"),
    "ecc-p256": ("prime256v1", "ec"),
    "ecc-p384": ("secp384r1", "ec"),
    "ecc-p521": ("secp521r1", "ec"),
}

VALIDITY_DAYS = {"root": 3650, "intermediate": 1825, "leaf": 365}


def run(cmd: list[str]) -> None:
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(
            f"FATAL: command gagal (exit {result.returncode}): {' '.join(cmd)}"
        )


def assert_openssl_supports_mldsa() -> str:
    openssl_path = shutil.which("openssl")
    if not openssl_path:
        raise SystemExit(
            "FATAL: openssl tidak ditemukan di PATH. Jalankan source env.sh dulu."
        )
    version = subprocess.run(
        [openssl_path, "version"], capture_output=True, text=True
    ).stdout.strip()
    algos = subprocess.run(
        [openssl_path, "list", "-signature-algorithms"],
        capture_output=True,
        text=True,
    ).stdout
    if "ML-DSA-44" not in algos:
        raise SystemExit(
            f"FATAL: openssl di PATH ({openssl_path}, {version}) tidak mendukung ML-DSA.\n"
            "Jalankan source env.sh di terminal ini sebelum menjalankan gen_pki.py."
        )
    print(f"Menggunakan: {openssl_path} ({version})")
    return openssl_path


def genkey(openssl: str, algo_code: str, key_path: Path) -> None:
    openssl_alg, kind = ALGORITHMS[algo_code]
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "mldsa":
        cmd = [openssl, "genpkey", "-algorithm", openssl_alg, "-out", str(key_path)]
    else:
        cmd = [
            openssl,
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            f"ec_paramgen_curve:{openssl_alg}",
            "-out",
            str(key_path),
        ]
    run(cmd)


def make_root(openssl: str, algo_code: str, out_dir: Path) -> None:
    key = out_dir / "root.key"
    crt = out_dir / "root.crt"
    genkey(openssl, algo_code, key)
    subject = f"/C=ID/O=PQC-TLS-Thesis/OU=Root-CA/CN=Root-CA-{algo_code}"
    run([
        openssl,
        "req",
        "-x509",
        "-new",
        "-key",
        str(key),
        "-out",
        str(crt),
        "-days",
        str(VALIDITY_DAYS["root"]),
        "-subj",
        subject,
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:1",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ])


def make_intermediate(openssl: str, algo_code: str, out_dir: Path) -> None:
    key = out_dir / "intermediate.key"
    csr = out_dir / "intermediate.csr"
    crt = out_dir / "intermediate.crt"
    root_key = out_dir / "root.key"
    root_crt = out_dir / "root.crt"
    ext_file = out_dir / "intermediate.ext"
    genkey(openssl, algo_code, key)
    subject = f"/C=ID/O=PQC-TLS-Thesis/OU=Intermediate-CA/CN=Intermediate-CA-{algo_code}"
    run([openssl, "req", "-new", "-key", str(key), "-out", str(csr), "-subj", subject])

    # WAJIB: basicConstraints CA:TRUE, kalau tidak openssl verify menolak
    # dengan "error 79: invalid CA certificate" saat cert ini menandatangani leaf.
    ext_file.write_text(
        "basicConstraints=critical,CA:TRUE,pathlen:0\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
    )
    run([
        openssl,
        "x509",
        "-req",
        "-in",
        str(csr),
        "-CA",
        str(root_crt),
        "-CAkey",
        str(root_key),
        "-CAcreateserial",
        "-out",
        str(crt),
        "-days",
        str(VALIDITY_DAYS["intermediate"]),
        "-extfile",
        str(ext_file),
    ])


def make_leaf(openssl: str, algo_code: str, out_dir: Path) -> None:
    key = out_dir / "leaf.key"
    csr = out_dir / "leaf.csr"
    crt = out_dir / "leaf.crt"
    inter_key = out_dir / "intermediate.key"
    inter_crt = out_dir / "intermediate.crt"
    ext_file = out_dir / "leaf.ext"
    genkey(openssl, algo_code, key)
    subject = "/C=ID/O=PQC-TLS-Thesis/OU=Leaf/CN=localhost"
    run([openssl, "req", "-new", "-key", str(key), "-out", str(csr), "-subj", subject])

    # Leaf: bukan CA. subjectAltName wajib untuk trust hostname modern.
    ext_file.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
    )
    run([
        openssl,
        "x509",
        "-req",
        "-in",
        str(csr),
        "-CA",
        str(inter_crt),
        "-CAkey",
        str(inter_key),
        "-CAcreateserial",
        "-out",
        str(crt),
        "-days",
        str(VALIDITY_DAYS["leaf"]),
        "-extfile",
        str(ext_file),
    ])


def main() -> None:
    openssl = assert_openssl_supports_mldsa()
    for algo_code in ALGORITHMS:
        out_dir = PKI_DIR / algo_code
        print(f"\n=== Hierarki: {algo_code} ===")
        make_root(openssl, algo_code, out_dir)
        make_intermediate(openssl, algo_code, out_dir)
        make_leaf(openssl, algo_code, out_dir)
        print(f"OK: {algo_code} -> {out_dir}")
    print("\nSemua 6 hierarki selesai di-generate.")
    print("Verifikasi (openssl verify) dilakukan di langkah terpisah, bukan di skrip ini.")


if __name__ == "__main__":
    main()
