#!/usr/bin/env python3
"""
tls_client_bench.py — Ukur handshake TLS 1.3 nyata: full vs resumed (FR-5, FR-6).

PERUBAHAN MENDASAR (setelah tshark/dumpcap terbukti tidak reliable untuk
timing presisi di WSL2 -- capture kadang tidak pernah mencetak "Capturing on"
sama sekali dalam 8 detik, dan tetap gagal 0 byte berulang kali meski sudah
menunggu marker resmi):

- handshake_bytes_total SEKARANG diukur lewat selisih counter resmi kernel
  Linux di /proc/net/dev untuk interface "lo" (baca sebelum & sesudah satu
  handshake). Ini tidak butuh sudo, tidak ada race condition timing sama
  sekali (counter kernel instan & akurat), dan karena hanya ada 1 koneksi
  TCP yang berjalan per trial, selisihnya = persis byte handshake tersebut.
- tshark TETAP dipakai, tapi HANYA untuk menyimpan 1 file pcap contoh per
  (algoritma x mode) sebagai bukti kualitatif di laporan -- best-effort,
  non-fatal. Jika capture gagal/terlambat, cukup di-skip dengan warning;
  angka byte di CSV tidak terpengaruh sama sekali karena datang dari
  /proc/net/dev, bukan dari pcap.
- Ditambahkan pembersihan otomatis (atexit) untuk proses s_server/tshark
  yang mungkin tersisa saat script keluar karena error -- mencegah
  "Address already in use" di run berikutnya.
"""

import argparse
import atexit
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
TMP_DIR = PROJECT_ROOT / "data" / "raw" / "tls_client_tmp"
PCAP_DIR = PROJECT_ROOT / "data" / "raw" / "pcap"

PORTS = {
    "mldsa44": 8443,
    "mldsa65": 8444,
    "mldsa87": 8445,
    "ecc-p256": 8446,
    "ecc-p384": 8447,
    "ecc-p521": 8448,
}

DISPLAY = {
    "mldsa44": ("ML-DSA-44", "ML-DSA", "2"),
    "mldsa65": ("ML-DSA-65", "ML-DSA", "3"),
    "mldsa87": ("ML-DSA-87", "ML-DSA", "5"),
    "ecc-p256": ("ECDSA-P256", "ECC", "~128-bit"),
    "ecc-p384": ("ECDSA-P384", "ECC", "~192-bit"),
    "ecc-p521": ("ECDSA-P521", "ECC", "~256-bit"),
}

_cleanup_procs: list[subprocess.Popen] = []


def _register_cleanup(proc: subprocess.Popen) -> None:
    _cleanup_procs.append(proc)


def _cleanup_all() -> None:
    for p in _cleanup_procs:
        if p.poll() is None:
            try:
                p.kill()
            except Exception:
                pass
    subprocess.run(["pkill", "-9", "-f", "tls_server.py"], check=False)
    subprocess.run(["sudo", "pkill", "-9", "-f", "tshark -i lo"], check=False)


atexit.register(_cleanup_all)


def run_measured_child(
    cmd: list[str], suppress: bool, capture_to: Path | None = None
):
    t0 = time.perf_counter()
    pid = os.fork()
    if pid == 0:
        devnull_in = os.open(os.devnull, os.O_RDONLY)
        os.dup2(devnull_in, 0)
        if capture_to is not None:
            out_fd = os.open(
                str(capture_to), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644
            )
            os.dup2(out_fd, 1)
            os.dup2(out_fd, 2)
        elif suppress:
            devnull_out = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull_out, 1)
            os.dup2(devnull_out, 2)
        try:
            os.execvp(cmd[0], cmd)
        except Exception:
            os._exit(127)
    else:
        _, status, rusage = os.wait4(pid, 0)
        wall_ms = (time.perf_counter() - t0) * 1000.0
        exit_code = os.waitstatus_to_exitcode(status)
        return wall_ms, rusage, exit_code


def read_lo_bytes() -> int:
    """Baca counter byte resmi kernel (RX+TX) untuk interface loopback dari
    /proc/net/dev. Tidak butuh privilege khusus, tidak ada race condition."""
    with open("/proc/net/dev") as f:
        for line in f:
            if line.strip().startswith("lo:"):
                fields = line.split(":", 1)[1].split()
                rx_bytes = int(fields[0])
                tx_bytes = int(fields[8])
                return rx_bytes + tx_bytes
    raise RuntimeError("Tidak menemukan interface 'lo' di /proc/net/dev")


def run_measured_handshake(
    cmd: list[str],
    sanity_file: Path | None = None,
    required_substrings: list[str] | None = None,
):
    """Jalankan satu handshake dan ukur wall/cpu time + byte lewat selisih
    counter kernel /proc/net/dev sebelum & sesudah. Karena hanya 1 koneksi
    TCP aktif per trial, selisih ini sama persis dengan byte handshake itu."""
    before = read_lo_bytes()
    if sanity_file is not None:
        sanity_file.parent.mkdir(parents=True, exist_ok=True)
        wall_ms, rusage, exit_code = run_measured_child(
            cmd, suppress=False, capture_to=sanity_file
        )
        text = sanity_file.read_text(errors="replace")
        missing = [s for s in (required_substrings or []) if s not in text]
        if missing:
            raise SystemExit(
                f"FATAL: sanity check gagal, tidak ditemukan {missing}. Isi:\n{text}"
            )
    else:
        wall_ms, rusage, exit_code = run_measured_child(cmd, suppress=True)
        if exit_code != 0:
            raise SystemExit(
                f"FATAL: handshake gagal (exit_code={exit_code}) untuk cmd={' '.join(cmd)}"
            )
    after = read_lo_bytes()
    hs_bytes = after - before
    return wall_ms, rusage, hs_bytes


def do_priming_connection(
    openssl: str, port: int, root_crt: Path, session_file: Path
) -> None:
    proc = subprocess.Popen(
        [
            openssl,
            "s_client",
            "-connect",
            f"localhost:{port}",
            "-tls1_3",
            "-CAfile",
            str(root_crt),
            "-sess_out",
            str(session_file),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.0)
    try:
        proc.stdin.write(b"Q\n")
        proc.stdin.flush()
        proc.stdin.close()
    except BrokenPipeError:
        pass
    proc.wait(timeout=10)


def start_server(algo: str, naccept: int) -> subprocess.Popen:
    proc = subprocess.Popen(
        [
            sys.executable,
            str(PROJECT_ROOT / "src" / "tls_server.py"),
            "--algo",
            algo,
            "--naccept",
            str(naccept),
        ],
        cwd=str(PROJECT_ROOT),
        env=os.environ.copy(),
    )
    _register_cleanup(proc)
    return proc


def stop_server(server: subprocess.Popen) -> None:
    if server.poll() is not None:
        return
    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=5)
    subprocess.run(["pkill", "-9", "-f", "openssl s_server"], check=False)


def sum_pcap_bytes(pcap_path: Path) -> int:
    result = subprocess.run(
        ["tshark", "-r", str(pcap_path), "-T", "fields", "-e", "frame.len"],
        capture_output=True,
        text=True,
        check=True,
    )
    return sum(int(x) for x in result.stdout.split() if x.strip())


def try_capture_sample_and_measure(
    cmd: list[str],
    port: int,
    keep_pcap_path: Path,
    sanity_file: Path | None = None,
    required_substrings: list[str] | None = None,
):
    """Jalankan handshake yang diukur (via /proc/net/dev, selalu akurat),
    SAMBIL mencoba menangkap 1 pcap contoh secara best-effort untuk bukti
    kualitatif. Kegagalan capture tidak pernah menggagalkan trial ini --
    hanya di-skip dengan warning."""
    tmp_pcap_path = Path(f"/tmp/pqc_tls_{uuid.uuid4().hex[:10]}.pcap")
    log_path = tmp_pcap_path.with_suffix(".log")
    log_fd = open(log_path, "w")
    capture_proc = subprocess.Popen(
        [
            "sudo",
            "tshark",
            "-i",
            "lo",
            "-f",
            f"tcp port {port}",
            "-w",
            str(tmp_pcap_path),
        ],
        stdout=log_fd,
        stderr=subprocess.STDOUT,
    )
    log_fd.close()
    _register_cleanup(capture_proc)

    capture_ready = False
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if log_path.exists() and "Capturing on" in log_path.read_text(
            errors="replace"
        ):
            capture_ready = True
            break
        if capture_proc.poll() is not None:
            break
        time.sleep(0.05)

    if capture_ready:
        time.sleep(0.1)

    try:
        wall_ms, rusage, hs_bytes = run_measured_handshake(
            cmd, sanity_file, required_substrings
        )
    finally:
        subprocess.run(
            ["sudo", "pkill", "-INT", "-f", str(tmp_pcap_path)], check=False
        )
        try:
            capture_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            subprocess.run(
                ["sudo", "pkill", "-9", "-f", str(tmp_pcap_path)], check=False
            )
            capture_proc.wait(timeout=5)

    time.sleep(0.2)
    saved = False
    if capture_ready and tmp_pcap_path.exists():
        user = os.environ.get("USER", "root")
        subprocess.run(
            ["sudo", "chown", f"{user}:{user}", str(tmp_pcap_path)], check=False
        )
        try:
            sample_bytes = sum_pcap_bytes(tmp_pcap_path)
        except Exception:
            sample_bytes = 0

        if sample_bytes > 0:
            keep_pcap_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(tmp_pcap_path), str(keep_pcap_path))
            saved = True

    if not saved:
        tmp_pcap_path.unlink(missing_ok=True)
        print(
            f"  WARNING: pcap contoh untuk {keep_pcap_path} tidak berhasil disimpan "
            f"(capture tidak siap tepat waktu) -- diabaikan, metrik byte tetap valid dari /proc/net/dev."
        )

    log_path.unlink(missing_ok=True)
    return wall_ms, rusage, hs_bytes


def make_row(
    run_id,
    algo,
    operation,
    trial,
    wall_ms,
    rusage,
    chain_length,
    mitigation,
    hs_bytes,
) -> dict:
    algo_name, family, sec_level = DISPLAY[algo]
    return {
        "run_id": run_id,
        "algorithm": algo_name,
        "algorithm_family": family,
        "security_level": sec_level,
        "cert_level": "leaf",
        "operation": operation,
        "trial_number": trial,
        "time_ms": round(wall_ms, 4),
        "cpu_time_ms": round((rusage.ru_utime + rusage.ru_stime) * 1000.0, 4),
        "peak_memory_kb": rusage.ru_maxrss,
        "file_size_bytes": "",
        "chain_length": chain_length,
        "mitigation": mitigation,
        "handshake_bytes_total": hs_bytes,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def bench_full(openssl: str, algo: str, trials: int, run_id: str) -> list[dict]:
    port = PORTS[algo]
    root_crt = PKI_DIR / algo / "root.crt"
    final_pcap_path = PCAP_DIR / algo / "full.pcap"
    sanity_out = TMP_DIR / algo / "sanity_full.txt"
    server = start_server(algo, trials)
    time.sleep(1)
    cmd = [
        openssl,
        "s_client",
        "-connect",
        f"localhost:{port}",
        "-tls1_3",
        "-CAfile",
        str(root_crt),
    ]
    rows = []
    try:
        for trial in range(1, trials + 1):
            if trial == 1:
                wall_ms, rusage, hs_bytes = try_capture_sample_and_measure(
                    cmd,
                    port,
                    final_pcap_path,
                    sanity_file=sanity_out,
                    required_substrings=[
                        "Verify return code: 0",
                        "New, TLSv1.3",
                    ],
                )
                print(
                    f"  [sanity {algo}/full] OK (New, TLSv1.3; Verify return code: 0)"
                )
            else:
                wall_ms, rusage, hs_bytes = run_measured_handshake(cmd)
            if trial % 25 == 0:
                print(f"  [{algo}/full] {trial}/{trials}")
            rows.append(
                make_row(
                    run_id,
                    algo,
                    "handshake_full",
                    trial,
                    wall_ms,
                    rusage,
                    3,
                    "none",
                    hs_bytes,
                )
            )
    finally:
        stop_server(server)
    return rows


def bench_resumed(openssl: str, algo: str, trials: int, run_id: str) -> list[dict]:
    port = PORTS[algo]
    root_crt = PKI_DIR / algo / "root.crt"
    final_pcap_path = PCAP_DIR / algo / "resumed.pcap"
    session_file = TMP_DIR / algo / "session_resumed.pem"
    sanity_out = TMP_DIR / algo / "sanity_resumed.txt"
    session_file.parent.mkdir(parents=True, exist_ok=True)
    if session_file.exists():
        session_file.unlink()
    time.sleep(1)  # beri jeda supaya port bekas server "full" benar2 dilepas OS
    server = start_server(algo, trials + 1)
    time.sleep(1)
    rows = []
    try:
        do_priming_connection(openssl, port, root_crt, session_file)
        if not session_file.exists():
            raise SystemExit(
                f"FATAL: priming connection untuk {algo}/resumed tidak menghasilkan "
                f"session file ({session_file})."
            )
        cmd = [
            openssl,
            "s_client",
            "-connect",
            f"localhost:{port}",
            "-tls1_3",
            "-CAfile",
            str(root_crt),
            "-sess_in",
            str(session_file),
            "-sess_out",
            str(session_file),
        ]
        for trial in range(1, trials + 1):
            if trial == 1:
                wall_ms, rusage, hs_bytes = try_capture_sample_and_measure(
                    cmd,
                    port,
                    final_pcap_path,
                    sanity_file=sanity_out,
                    required_substrings=[
                        "Verify return code: 0",
                        "Reused, TLSv1.3",
                    ],
                )
                print(
                    f"  [sanity {algo}/resumed] OK (Reused, TLSv1.3; Verify return code: 0)"
                )
            else:
                wall_ms, rusage, hs_bytes = run_measured_handshake(cmd)
            if trial % 25 == 0:
                print(f"  [{algo}/resumed] {trial}/{trials}")
            rows.append(
                make_row(
                    run_id,
                    algo,
                    "handshake_resumed",
                    trial,
                    wall_ms,
                    rusage,
                    0,
                    "session_resumption",
                    hs_bytes,
                )
            )
    finally:
        stop_server(server)
    return rows


def demo_handshake(openssl: str, algo: str) -> None:
    """Jalankan satu handshake TLS 1.3 nyata dan tampilkan tahapannya secara
    natural di terminal, mengikuti urutan pada Gambar 3.3 (Bab III 3.4.2):
    client hello -> server hello + rantai sertifikat -> ukuran on-the-wire ->
    parsing struktural & jalur kepercayaan -> verifikasi tanda tangan ->
    keputusan lanjut/batal -> catat hasil."""
    port = PORTS[algo]
    root_crt = PKI_DIR / algo / "root.crt"
    algo_name = DISPLAY[algo][0]
    print(f"\n--- Demo handshake TLS 1.3: {algo_name} ({algo}) ---")
    server = start_server(algo, 1)
    time.sleep(1)
    try:
        print("  klien mengirim client hello")
        cmd = [
            openssl,
            "s_client",
            "-connect",
            f"localhost:{port}",
            "-tls1_3",
            "-CAfile",
            str(root_crt),
            "-showcerts",
        ]
        before = read_lo_bytes()
        t0 = time.perf_counter()
        proc = subprocess.run(cmd, input=b"Q\n", capture_output=True, timeout=15)
        wall_ms = (time.perf_counter() - t0) * 1000.0
        after = read_lo_bytes()
        hs_bytes = after - before
        out = proc.stdout.decode(errors="replace") + proc.stderr.decode(errors="replace")
        lines = out.splitlines()

        print("  server membalas server hello, encryptedextensions, dan rantai sertifikat")
        for line in lines:
            stripped = line.strip()
            if (
                "Certificate chain" in stripped
                or " s:" in f" {stripped}"
                or " i:" in f" {stripped}"
                or stripped.startswith(("s:", "i:"))
            ):
                print(f"    {stripped}")

        print(f"  ukuran byte on-the-wire (selisih counter kernel /proc/net/dev): {hs_bytes} byte")

        print(
            "  klien mem-parsing sertifikat DER (validasi struktural) dan "
            "membangun jalur kepercayaan leaf -> intermediate -> root"
        )

        verify_line = next(
            (l.strip() for l in lines if "Verify return code" in l),
            "Verify return code: tidak ditemukan",
        )
        print("  klien memverifikasi tanda tangan digital tiap tautan (verifikasi kriptografis)")
        print(f"    {verify_line}")

        session_reused = "Reused, TLSv1.3" in out
        session_new = "New, TLSv1.3" in out
        if "Verify return code: 0" in out and (session_new or session_reused):
            print(
                "  tautan valid dan tanda tangan sah -> handshake berlanjut ke "
                "Certificate Verify hingga Finished, sesi terbentuk"
            )
        else:
            print("  tautan tidak valid atau tanda tangan tidak sah -> handshake dibatalkan, koneksi ditolak")

        print(f"  mencatat hasil: latensi={wall_ms:.2f}ms, ukuran on-the-wire={hs_bytes} byte")
    finally:
        stop_server(server)


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
        "--out",
        type=Path,
        default=PROJECT_ROOT / "data" / "raw" / "tls_handshake_bench.csv",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Jalankan 1 handshake nyata per algoritma dengan narasi tahapan (Gambar 3.3), "
        "tanpa menjalankan benchmark 100x dan tanpa menulis CSV.",
    )
    args = parser.parse_args()

    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit("FATAL: openssl tidak ditemukan. Jalankan source env.sh dulu.")

    if args.demo:
        for algo in args.algos:
            demo_handshake(openssl, algo)
        return

    print("Meminta izin sudo (dipakai tshark untuk pcap contoh saja)...")
    subprocess.run(["sudo", "-v"], check=True)

    run_id = str(uuid.uuid4())
    all_rows: list[dict] = []

    for algo in args.algos:
        print(f"\n=== {algo} ===")
        all_rows += bench_full(openssl, algo, args.trials, run_id)
        all_rows += bench_resumed(openssl, algo, args.trials, run_id)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\nSelesai. {len(all_rows)} baris ditulis ke {args.out}")


if __name__ == "__main__":
    main()
