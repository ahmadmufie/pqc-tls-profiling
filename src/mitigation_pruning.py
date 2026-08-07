#!/usr/bin/env python3
"""
mitigation_pruning.py — FR-7: Ukur efek chain pruning terhadap
handshake_bytes_total.

Chain pruning menguji 3 varian panjang sertifikat yang dikirim server saat
handshake TLS 1.3 (bukan mengubah algoritma tanda tangan itu sendiri):
  - full      (chain_length=3): leaf + intermediate + root -- baseline
  - no-root   (chain_length=2): leaf + intermediate saja. Client tetap bisa
                membangun rantai kepercayaan penuh sendiri karena root
                sudah ada di trust store client (-CAfile root.crt) --
                mengirim root lagi memang mubazir di TLS 1.3.
  - leaf-only (chain_length=1): leaf saja. Server tidak mengirim
                intermediate sama sekali. Secara default client TIDAK BISA
                memverifikasi rantai (verify return code 21, "unable to
                verify the first certificate") karena tidak tahu
                sertifikat intermediate mana yang menjembatani leaf ke
                root.

SIMULASI RFC 7924 (Cached Information Extension) untuk leaf-only:
  Di produksi nyata, chain pruning seagresif ini hanya masuk akal jika
  client SUDAH memiliki salinan sertifikat intermediate dari sesi
  sebelumnya (itulah gagasan RFC 7924 -- client memberi tahu server
  sertifikat mana yang sudah di-cache, sehingga server tidak perlu
  mengirimnya ulang). OpenSSL CLI yang dipakai di sini tidak
  mengimplementasikan ekstensi tersebut, dan build s_client yang dipakai
  bahkan tidak punya flag -untrusted untuk membantu path-building tanpa
  menambah trust anchor baru. Maka efeknya DISIMULASIKAN dengan cara yang
  paling portable: khusus untuk leaf-only, client diberi -CAfile gabungan
  (root.crt + intermediate.crt) sehingga secara efektif client "sudah
  mempercayai/menyimpan" intermediate itu (menyerupai efek cache RFC
  7924). Ini eksplisit sebuah simulasi, bukan pruning yang berjalan murni
  di wire seperti no-root -- harus dijelaskan sebagai batasan penelitian
  di laporan (lihat PRD Bagian 13).

Server (tls_server.py) sudah mendukung --chain-mode untuk memilih file
cert_chain_<mode>.pem yang sesuai. Skrip ini memakai ulang mesin
pengukuran dari tls_client_bench.py (byte diukur lewat delta counter
kernel /proc/net/dev, metodologi yang sama seperti M3) supaya hasil
full vs no-root vs leaf-only bisa dibandingkan apple-to-apple.
"""

import argparse
import csv
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tls_client_bench import (
    PCAP_DIR,
    PKI_DIR,
    PORTS,
    PROJECT_ROOT,
    TMP_DIR,
    _register_cleanup,
    make_row,
    run_measured_handshake,
    stop_server,
    try_capture_sample_and_measure,
)

CHAIN_MODES = {
    "full": 3,
    "no-root": 2,
    "leaf-only": 1,
}


def start_server_with_mode(
    algo: str, chain_mode: str, naccept: int
) -> subprocess.Popen:
    proc = subprocess.Popen(
        [
            sys.executable,
            str(PROJECT_ROOT / "src" / "tls_server.py"),
            "--algo",
            algo,
            "--chain-mode",
            chain_mode,
            "--naccept",
            str(naccept),
        ],
        cwd=str(PROJECT_ROOT),
        env=os.environ.copy(),
    )
    _register_cleanup(proc)
    return proc


def resolve_cafile(algo: str, chain_mode: str) -> Path:
    """Tentukan file -CAfile yang dipakai client untuk memverifikasi server.
    Untuk full dan no-root, cukup root.crt saja (client sudah mempercayai
    root secara normal). Untuk leaf-only, gabungkan root.crt +
    intermediate.crt jadi satu file sementara -- ini MENSIMULASIKAN client
    yang sudah meng-cache intermediate dari sesi sebelumnya (efek RFC
    7924), karena server tidak mengirim intermediate itu sama sekali di
    mode ini.
    """
    root_crt = PKI_DIR / algo / "root.crt"
    if chain_mode != "leaf-only":
        return root_crt
    intermediate_crt = PKI_DIR / algo / "intermediate.crt"
    combined = TMP_DIR / algo / "cafile_leaf_only_sim.pem"
    combined.parent.mkdir(parents=True, exist_ok=True)
    combined.write_text(root_crt.read_text() + intermediate_crt.read_text())
    return combined


def build_client_cmd(
    openssl: str, algo: str, port: int, chain_mode: str
) -> list[str]:
    cafile = resolve_cafile(algo, chain_mode)
    return [
        openssl,
        "s_client",
        "-connect",
        f"localhost:{port}",
        "-tls1_3",
        "-CAfile",
        str(cafile),
    ]


def bench_pruning_mode(
    openssl: str, algo: str, chain_mode: str, trials: int, run_id: str
) -> list[dict]:
    port = PORTS[algo]
    chain_length = CHAIN_MODES[chain_mode]
    mitigation = "none" if chain_mode == "full" else "pruning"
    pcap_path = PCAP_DIR / algo / f"pruning_{chain_mode}.pcap"
    sanity_out = TMP_DIR / algo / f"sanity_pruning_{chain_mode}.txt"
    server = start_server_with_mode(algo, chain_mode, trials)
    time.sleep(1)
    cmd = build_client_cmd(openssl, algo, port, chain_mode)
    rows = []
    try:
        for trial in range(1, trials + 1):
            if trial == 1:
                wall_ms, rusage, hs_bytes = try_capture_sample_and_measure(
                    cmd,
                    port,
                    pcap_path,
                    sanity_file=sanity_out,
                    required_substrings=[
                        "Verify return code: 0",
                        "New, TLSv1.3",
                    ],
                )
                print(
                    f"  [sanity {algo}/{chain_mode}] OK (New, TLSv1.3; Verify return code: 0)"
                )
            else:
                wall_ms, rusage, hs_bytes = run_measured_handshake(cmd)
            if trial % 25 == 0:
                print(f"  [{algo}/{chain_mode}] {trial}/{trials}")
            rows.append(
                make_row(
                    run_id,
                    algo,
                    "handshake_full",
                    trial,
                    wall_ms,
                    rusage,
                    chain_length,
                    mitigation,
                    hs_bytes,
                )
            )
    finally:
        stop_server(server)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=100)
    parser.add_argument(
        "--algos",
        nargs="+",
        default=list(PORTS.keys()),
        choices=list(PORTS.keys()),
    )
    parser.add_argument(
        "--modes",
        nargs="+",
        default=list(CHAIN_MODES.keys()),
        choices=list(CHAIN_MODES.keys()),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=PROJECT_ROOT / "data" / "raw" / "chain_pruning_bench.csv",
    )
    args = parser.parse_args()

    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit(
            "FATAL: openssl tidak ditemukan. Jalankan source env.sh dulu."
        )

    print("Meminta izin sudo (dipakai tshark untuk pcap contoh saja)...")
    subprocess.run(["sudo", "-v"], check=True)

    run_id = str(uuid.uuid4())
    all_rows: list[dict] = []

    for algo in args.algos:
        print(f"\n=== {algo} ===")
        for mode in args.modes:
            print(f" -- chain-mode: {mode} (chain_length={CHAIN_MODES[mode]})")
            all_rows += bench_pruning_mode(
                openssl, algo, mode, args.trials, run_id
            )
            time.sleep(1)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\nSelesai. {len(all_rows)} baris ditulis ke {args.out}")


if __name__ == "__main__":
    main()
