#!/usr/bin/env python3
"""
bench_crypto.py — Ukur time/CPU/memory untuk keygen, sign, verify (FR-4).

Mekanisme harness (WAJIB CUSTOM per PRD Bagian 4):
- Tiap trial dijalankan sebagai child process `openssl` terpisah lewat
  os.fork() + os.execvp(), lalu diukur dengan os.wait4(pid, 0).
- os.wait4 mengembalikan `rusage` MILIK CHILD PROCESS ITU SENDIRI SAJA
  (ru_utime, ru_stime, ru_maxrss). Ini presisi per-trial. Berbeda dengan
  subprocess.run()+resource.getrusage(RUSAGE_CHILDREN), yang nilainya
  terakumulasi dari SEMUA child process sebelumnya sejak proses Python
  dimulai — tidak bisa diisolasi per trial.
- Wall-clock diukur terpisah dengan time.perf_counter() di parent,
  membungkus fork+exec+wait.

Perbedaan API openssl per keluarga algoritma (wajib dipahami, bukan disamakan):
- ECDSA adalah skema "hash-then-sign": pesan di-hash dulu (mis. SHA-256),
  baru digest itu yang ditandatangani. `pkeyutl -sign -rawin -digest sha256`
  artinya "hash pesan mentah dengan sha256 dulu di dalam pkeyutl, baru sign".
- ML-DSA adalah skema "pure signature": seluruh pesan mentah masuk langsung
  ke algoritma tanda tangan, tanpa hashing eksternal. Maka TIDAK memakai
  `-digest`; cukup `pkeyutl -sign -rawin` saja.
  Kalau `-digest` dipaksakan ke kunci ML-DSA, openssl akan error.

Operasi yang diukur:
- keygen : generate keypair baru dari nol (algoritma sesuai hierarki).
- sign   : tanda tangani pesan tetap 1 KB pakai leaf.key hierarki tsb.
- verify : verifikasi signature (dibuat sekali di awal) terhadap leaf.pub.
"""

import argparse
import csv
import os
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PKI_DIR = PROJECT_ROOT / "pki"
TMP_DIR = PROJECT_ROOT / "data" / "raw" / "bench_tmp"
MSG_PATH = PROJECT_ROOT / "data" / "raw" / "bench_message.bin"
MSG_SIZE_BYTES = 1024

# algo_code -> (openssl genpkey arg, kind, digest_for_sign_or_None, algorithm display name, family, security_level)
ALGORITHMS = {
    "mldsa44": ("ML-DSA-44", "mldsa", None, "ML-DSA-44", "ML-DSA", "2"),
    "mldsa65": ("ML-DSA-65", "mldsa", None, "ML-DSA-65", "ML-DSA", "3"),
    "mldsa87": ("ML-DSA-87", "mldsa", None, "ML-DSA-87", "ML-DSA", "5"),
    "ecc-p256": ("prime256v1", "ec", "sha256", "ECDSA-P256", "ECC", "~128-bit"),
    "ecc-p384": ("secp384r1", "ec", "sha384", "ECDSA-P384", "ECC", "~192-bit"),
    "ecc-p521": ("secp521r1", "ec", "sha512", "ECDSA-P521", "ECC", "~256-bit"),
}


def assert_openssl_supports_mldsa() -> str:
    openssl_path = shutil.which("openssl")
    if not openssl_path:
        raise SystemExit(
            "FATAL: openssl tidak ditemukan di PATH. Jalankan source env.sh dulu."
        )
    algos = subprocess.run(
        [openssl_path, "list", "-signature-algorithms"],
        capture_output=True,
        text=True,
    ).stdout
    if "ML-DSA-44" not in algos:
        raise SystemExit(
            f"FATAL: openssl di PATH ({openssl_path}) tidak mendukung ML-DSA."
        )
    return openssl_path


def run_measured_child(
    cmd: list[str], suppress_output: bool
) -> tuple[float, "os.times_result", int]:
    """
    Jalankan satu command sebagai child process, ukur wall time (parent) dan
    rusage (child, via os.wait4). Mengembalikan (wall_ms, rusage, exit_code).
    """
    t0 = time.perf_counter()
    pid = os.fork()
    if pid == 0:
        # ---- child process ----
        if suppress_output:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
        try:
            os.execvp(cmd[0], cmd)
        except Exception:
            os._exit(127)
        # tidak pernah sampai sini
    else:
        # ---- parent process ----
        _, status, rusage = os.wait4(pid, 0)
        wall_ms = (time.perf_counter() - t0) * 1000.0
        exit_code = os.waitstatus_to_exitcode(status)
        return wall_ms, rusage, exit_code


def sanity_check(cmd: list[str], label: str) -> None:
    """Jalankan sekali TANPA suppress output, supaya error langsung terlihat."""
    wall_ms, rusage, exit_code = run_measured_child(cmd, suppress_output=False)
    if exit_code != 0:
        raise SystemExit(
            f"FATAL: sanity check gagal untuk {label} (exit {exit_code}): {' '.join(cmd)}"
        )


def bench_keygen(
    openssl: str, algo_code: str, trials: int, rows: list, run_id: str
) -> None:
    openssl_alg, kind, _, algo_name, family, sec_level = ALGORITHMS[algo_code]
    out_dir = TMP_DIR / algo_code
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / "keygen_bench.key"

    def build_cmd() -> list[str]:
        if kind == "mldsa":
            return [
                openssl,
                "genpkey",
                "-algorithm",
                openssl_alg,
                "-out",
                str(key_path),
            ]
        return [
            openssl,
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            f"ec_paramgen_curve:{openssl_alg}",
            "-out",
            str(key_path),
        ]

    sanity_check(build_cmd(), f"{algo_code}/keygen")
    for trial in range(1, trials + 1):
        wall_ms, rusage, exit_code = run_measured_child(
            build_cmd(), suppress_output=True
        )
        if exit_code != 0:
            raise SystemExit(
                f"FATAL: keygen gagal di trial {trial} untuk {algo_code}"
            )
        rows.append(
            make_row(
                run_id,
                algo_name,
                family,
                sec_level,
                "leaf",
                "keygen",
                trial,
                wall_ms,
                rusage,
                key_path.stat().st_size,
            )
        )
        if trial % 50 == 0:
            print(f"  [{algo_code}/keygen] {trial}/{trials}")


def bench_sign(
    openssl: str, algo_code: str, trials: int, rows: list, run_id: str
) -> None:
    openssl_alg, kind, digest, algo_name, family, sec_level = ALGORITHMS[algo_code]
    leaf_key = PKI_DIR / algo_code / "leaf.key"
    out_dir = TMP_DIR / algo_code
    out_dir.mkdir(parents=True, exist_ok=True)
    sig_path = out_dir / "sign_bench.sig"

    def build_cmd() -> list[str]:
        cmd = [openssl, "pkeyutl", "-sign", "-rawin"]
        if digest:  # ECDSA: hash-then-sign
            cmd += ["-digest", digest]
        cmd += [
            "-inkey",
            str(leaf_key),
            "-in",
            str(MSG_PATH),
            "-out",
            str(sig_path),
        ]
        return cmd

    sanity_check(build_cmd(), f"{algo_code}/sign")
    for trial in range(1, trials + 1):
        wall_ms, rusage, exit_code = run_measured_child(
            build_cmd(), suppress_output=True
        )
        if exit_code != 0:
            raise SystemExit(
                f"FATAL: sign gagal di trial {trial} untuk {algo_code}"
            )
        rows.append(
            make_row(
                run_id,
                algo_name,
                family,
                sec_level,
                "leaf",
                "sign",
                trial,
                wall_ms,
                rusage,
                sig_path.stat().st_size,
            )
        )
        if trial % 50 == 0:
            print(f"  [{algo_code}/sign] {trial}/{trials}")


def bench_verify(
    openssl: str, algo_code: str, trials: int, rows: list, run_id: str
) -> None:
    openssl_alg, kind, digest, algo_name, family, sec_level = ALGORITHMS[algo_code]
    leaf_key = PKI_DIR / algo_code / "leaf.key"
    out_dir = TMP_DIR / algo_code
    out_dir.mkdir(parents=True, exist_ok=True)
    pub_path = out_dir / "leaf.pub"
    sig_path = out_dir / "verify_bench.sig"

    # Public key & signature referensi dibuat SEKALI (bukan per trial) --
    # verify harus memverifikasi signature yang valid & konsisten tiap trial.
    subprocess.run(
        [openssl, "pkey", "-in", str(leaf_key), "-pubout", "-out", str(pub_path)],
        check=True,
    )
    sign_cmd = [openssl, "pkeyutl", "-sign", "-rawin"]
    if digest:
        sign_cmd += ["-digest", digest]
    sign_cmd += [
        "-inkey",
        str(leaf_key),
        "-in",
        str(MSG_PATH),
        "-out",
        str(sig_path),
    ]
    subprocess.run(sign_cmd, check=True)

    def build_cmd() -> list[str]:
        cmd = [openssl, "pkeyutl", "-verify", "-rawin"]
        if digest:
            cmd += ["-digest", digest]
        cmd += [
            "-pubin",
            "-inkey",
            str(pub_path),
            "-in",
            str(MSG_PATH),
            "-sigfile",
            str(sig_path),
        ]
        return cmd

    sanity_check(build_cmd(), f"{algo_code}/verify")
    for trial in range(1, trials + 1):
        wall_ms, rusage, exit_code = run_measured_child(
            build_cmd(), suppress_output=True
        )
        if exit_code != 0:
            raise SystemExit(
                f"FATAL: verify gagal di trial {trial} untuk {algo_code} (signature tidak valid?)"
            )
        rows.append(
            make_row(
                run_id,
                algo_name,
                family,
                sec_level,
                "leaf",
                "verify",
                trial,
                wall_ms,
                rusage,
                sig_path.stat().st_size,
            )
        )
        if trial % 50 == 0:
            print(f"  [{algo_code}/verify] {trial}/{trials}")


def make_row(
    run_id,
    algorithm,
    family,
    sec_level,
    cert_level,
    operation,
    trial,
    wall_ms,
    rusage,
    file_size_bytes,
) -> dict:
    cpu_time_ms = (rusage.ru_utime + rusage.ru_stime) * 1000.0
    return {
        "run_id": run_id,
        "algorithm": algorithm,
        "algorithm_family": family,
        "security_level": sec_level,
        "cert_level": cert_level,
        "operation": operation,
        "trial_number": trial,
        "time_ms": round(wall_ms, 4),
        "cpu_time_ms": round(cpu_time_ms, 4),
        "peak_memory_kb": rusage.ru_maxrss,  # Linux: sudah dalam KB
        "file_size_bytes": file_size_bytes,
        "chain_length": "",  # tidak relevan untuk operasi ini
        "mitigation": "none",
        "handshake_bytes_total": "",  # tidak relevan untuk operasi ini
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=300)
    parser.add_argument(
        "--out",
        type=Path,
        default=PROJECT_ROOT / "data" / "raw" / "bench_crypto.csv",
    )
    args = parser.parse_args()

    openssl = assert_openssl_supports_mldsa()
    print(f"openssl: {openssl}")
    print(f"trials per (algoritma x operasi): {args.trials}")

    TMP_DIR.mkdir(parents=True, exist_ok=True)
    if not MSG_PATH.exists():
        MSG_PATH.parent.mkdir(parents=True, exist_ok=True)
        MSG_PATH.write_bytes(os.urandom(MSG_SIZE_BYTES))
    print(f"pesan benchmark: {MSG_PATH} ({MSG_PATH.stat().st_size} bytes)")

    run_id = str(uuid.uuid4())
    rows: list[dict] = []

    for algo_code in ALGORITHMS:
        print(f"\n=== {algo_code} ===")
        bench_keygen(openssl, algo_code, args.trials, rows, run_id)
        bench_sign(openssl, algo_code, args.trials, rows, run_id)
        bench_verify(openssl, algo_code, args.trials, rows, run_id)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSelesai. {len(rows)} baris ditulis ke {args.out}")


if __name__ == "__main__":
    main()
