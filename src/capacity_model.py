#!/usr/bin/env python3
"""
capacity_model.py — M5/FR-9: Estimasi & validasi empiris kapasitas server
(jumlah koneksi TLS 1.3 konkuren maksimum) per kombinasi algoritma x
mitigasi.

Scope: 6 algoritma x 2 kondisi mitigasi (none = baseline penuh,
resumption = PSK-based session resumption). Chain pruning ditunda dari M5
supaya scope terkendali -- bisa jadi eksperimen tambahan kalau waktu
masih ada.

Dua bagian:
1. ESTIMASI TEORETIS (est_max_concurrent)
   Dihitung dari rata-rata cpu_time_ms per kombinasi di data/results.csv:
       est_max_concurrent ~= server_cores / (cpu_time_ms_rata2 / 1000)
   Ini throughput maksimum teoretis KALAU CPU adalah satu-satunya
   bottleneck (mengabaikan I/O, jaringan, kontensi lock OpenSSL) --
   simplifikasi yang harus disebutkan eksplisit sebagai batasan di bab
   metodologi skripsi.

2. VALIDASI EMPIRIS (measured_max_concurrent)
   Load generator custom (bukan tool black-box seperti ab/wrk, sesuai
   batasan akademis PRD Bagian 4): menaikkan jumlah thread client
   konkuren bertahap, tiap thread menjalankan openssl s_client ASLI
   (bukan simulasi).

   CATATAN METODOLOGI PENTING #1: `openssl s_server` yang kita pakai
   (tanpa `-multi`) bersifat SERIAL -- ia memproses satu koneksi pada
   satu waktu, koneksi lain mengantre di backlog TCP. Akibatnya CPU%
   host TIDAK cukup sensitif untuk mendeteksi kejenuhan (client dan
   server berbagi mesin yang sama, dan proses klien sendiri turut
   menyumbang ke CPU% total sistem). Sinyal saturasi yang lebih valid
   di sini adalah LATENSI ANTREAN: jika latensi rata-rata pada suatu
   level pengujian melonjak >= LATENCY_SATURATION_FACTOR x latensi
   baseline (level pengujian pertama yang 100% berhasil), itu tanda
   antrean sudah menumpuk melebihi kapasitas layanan yang stabil.
   Kegagalan handshake (client timeout) juga tetap dihitung sebagai
   saturasi. CPU% tetap direkam sebagai diagnostik pendukung dan
   dilaporkan di kolom cpu_percent_at_saturation sesuai skema PRD.

   CATATAN METODOLOGI PENTING #2: karena setiap level beban membuka dan
   menutup ratusan/ribuan koneksi TCP localhost dengan cepat, socket bisa
   menumpuk dalam state TIME_WAIT dan mencemari pengukuran kombinasi
   berikutnya (bukan mencerminkan beban kerja algoritma yang sedang
   diuji). Sebelum setiap kombinasi algoritma x mitigasi diukur, skrip
   ini menunggu socket TIME_WAIT mereda (lihat wait_for_clean_sockets)
   supaya setiap kombinasi diuji dari kondisi host yang bersih dan bisa
   dibandingkan secara adil.

Output: data/capacity_profile.csv
   algorithm, mitigation, server_cores, est_max_concurrent,
   measured_max_concurrent, cpu_percent_at_saturation
"""

import argparse
import csv
import os
import shutil
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tls_client_bench import (
    DISPLAY,
    PKI_DIR,
    PORTS,
    PROJECT_ROOT,
    TMP_DIR,
    do_priming_connection,
    start_server,
    stop_server,
)

RESULTS_CSV = PROJECT_ROOT / "data" / "results.csv"
OUT_PATH = PROJECT_ROOT / "data" / "capacity_profile.csv"
DEFAULT_LEVELS = [5, 10, 20, 40, 80, 120, 160, 200]
SATURATION_CPU_PCT = 90.0  # diagnostik sekunder, bukan pemicu utama
LATENCY_SATURATION_FACTOR = 3.0  # level dianggap jenuh jika latensi >= 3x baseline
SAMPLER_INTERVAL_S = 0.25


def estimate_from_results(
    algo_code: str, mitigation: str, cores: int
) -> float | None:
    """Hitung est_max_concurrent dari rata-rata cpu_time_ms di results.csv."""
    algo_name, _, _ = DISPLAY[algo_code]
    operation = (
        "handshake_resumed" if mitigation == "resumption" else "handshake_full"
    )
    mitigation_col = (
        "session_resumption" if mitigation == "resumption" else "none"
    )
    cpu_times = []
    with RESULTS_CSV.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if (
                row["algorithm"] == algo_name
                and row["operation"] == operation
                and row["mitigation"] == mitigation_col
                and row["cpu_time_ms"]
            ):
                cpu_times.append(float(row["cpu_time_ms"]))
    if not cpu_times:
        return None
    avg_cpu_ms = statistics.mean(cpu_times)
    return cores / (avg_cpu_ms / 1000.0)


def do_one_handshake(
    openssl: str, port: int, root_crt: Path, session_file: Path | None
) -> tuple[bool, float]:
    """Satu handshake TLS nyata. Stdin memakai DEVNULL (EOF langsung),
    metode yang sudah terbukti membuat s_client keluar bersih setelah
    handshake selesai (tanpa -quiet di server, tanpa perlu kirim 'Q')."""
    cmd = [
        openssl,
        "s_client",
        "-connect",
        f"localhost:{port}",
        "-tls1_3",
        "-CAfile",
        str(root_crt),
    ]
    if session_file is not None:
        cmd += ["-sess_in", str(session_file)]
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        wall_ms = (time.perf_counter() - t0) * 1000.0
        return proc.returncode == 0, wall_ms
    except subprocess.TimeoutExpired:
        return False, (time.perf_counter() - t0) * 1000.0


def count_time_wait_sockets() -> int:
    """Hitung jumlah socket TCP dalam state TIME_WAIT di seluruh host.
    Dipakai untuk memastikan sisa koneksi dari kombinasi sebelumnya sudah
    reda sebelum mengukur kombinasi berikutnya -- mencegah TIME_WAIT
    menumpuk lalu mencemari latensi kombinasi yang diuji belakangan."""
    try:
        out = subprocess.run(
            ["ss", "-tanH", "state", "time-wait"],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
        return len([line for line in out.splitlines() if line.strip()])
    except Exception:
        return 0


def wait_for_clean_sockets(
    max_wait_s: float = 120.0, poll_interval_s: float = 3.0, threshold: int = 50
) -> None:
    """Tunggu sampai jumlah socket TIME_WAIT turun di bawah threshold,
    maksimum max_wait_s detik, sebelum mengizinkan kombinasi berikutnya
    diukur."""
    start = time.time()
    n = count_time_wait_sockets()
    while n > threshold and (time.time() - start) < max_wait_s:
        print(f"    menunggu socket TIME_WAIT mereda... ({n} tersisa)")
        time.sleep(poll_interval_s)
        n = count_time_wait_sockets()
    if n > threshold:
        print(
            f"    -- lanjut walau TIME_WAIT belum bersih total ({n} tersisa) setelah {max_wait_s:.0f}s"
        )
    else:
        print(f"    socket TIME_WAIT sudah reda ({n} tersisa). Lanjut.")


def cpu_sampler(stop_event: threading.Event, samples: list[float]) -> None:
    while not stop_event.is_set():
        samples.append(psutil.cpu_percent(interval=SAMPLER_INTERVAL_S))


def run_load_level(
    openssl: str,
    port: int,
    root_crt: Path,
    session_file: Path | None,
    concurrency: int,
) -> tuple[float, float, float]:
    """Jalankan satu level beban: concurrency handshake TLS konkuren
    sekaligus. Kembalikan (success_rate, avg_cpu_percent, avg_latency_ms_sukses).
    Latensi dipakai sebagai sinyal utama saturasi karena server s_server
    bersifat serial (satu koneksi diproses pada satu waktu) -- CPU% saja
    tidak cukup sensitif untuk mendeteksi antrean yang menumpuk."""
    samples: list[float] = []
    stop_event = threading.Event()
    sampler = threading.Thread(
        target=cpu_sampler, args=(stop_event, samples), daemon=True
    )
    sampler.start()
    results: list[tuple[bool, float] | None] = [None] * concurrency

    def worker(idx: int) -> None:
        results[idx] = do_one_handshake(openssl, port, root_crt, session_file)

    threads = [
        threading.Thread(target=worker, args=(i,)) for i in range(concurrency)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    stop_event.set()
    sampler.join(timeout=2)
    success_latencies = [r[1] for r in results if r and r[0]]
    successes = len(success_latencies)
    success_rate = successes / concurrency
    avg_cpu = statistics.mean(samples) if samples else 0.0
    avg_latency = statistics.mean(success_latencies) if success_latencies else 0.0
    return success_rate, avg_cpu, avg_latency


def measure_capacity(
    openssl: str, algo_code: str, mitigation: str, levels: list[int]
) -> tuple[int, float]:
    """Naikkan level konkurensi bertahap sampai saturasi. Kembalikan
    (measured_max_concurrent, cpu_percent_at_saturation)."""
    port = PORTS[algo_code]
    root_crt = PKI_DIR / algo_code / "root.crt"
    total_conns_needed = (
        sum(levels) + (1 if mitigation == "resumption" else 0) + 5
    )
    server = start_server(algo_code, total_conns_needed)
    time.sleep(1)
    session_file = None
    try:
        if mitigation == "resumption":
            session_file = TMP_DIR / algo_code / "session_capacity.pem"
            session_file.parent.mkdir(parents=True, exist_ok=True)
            if session_file.exists():
                session_file.unlink()
            do_priming_connection(openssl, port, root_crt, session_file)
            if not session_file.exists():
                raise SystemExit(
                    f"FATAL: priming resumption gagal untuk {algo_code} (capacity test)"
                )
        best_level = 0
        cpu_at_best = 0.0
        baseline_latency = None
        for level in levels:
            success_rate, avg_cpu, avg_latency = run_load_level(
                openssl, port, root_crt, session_file, level
            )
            print(
                f"    concurrency={level:4d}  success_rate={success_rate*100:5.1f}%  "
                f"avg_cpu={avg_cpu:5.1f}%  avg_latency={avg_latency:7.1f}ms"
            )
            if baseline_latency is None and success_rate >= 1.0:
                baseline_latency = avg_latency
            latency_blew_up = (
                baseline_latency is not None
                and avg_latency >= LATENCY_SATURATION_FACTOR * baseline_latency
            )
            if success_rate >= 1.0 and not latency_blew_up:
                best_level = level
                cpu_at_best = avg_cpu
            else:
                reason = (
                    "kegagalan handshake"
                    if success_rate < 1.0
                    else "latensi melonjak (antrean menumpuk)"
                )
                print(
                    f"    -- saturasi terdeteksi di concurrency={level} ({reason}), berhenti menaikkan beban"
                )
                if best_level == 0:
                    best_level = level
                    cpu_at_best = avg_cpu
                break
            time.sleep(1)  # beri jeda supaya CPU turun sebelum level berikutnya
        return best_level, cpu_at_best
    finally:
        stop_server(server)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--algos",
        nargs="+",
        default=list(PORTS.keys()),
        choices=list(PORTS.keys()),
    )
    parser.add_argument(
        "--mitigations",
        nargs="+",
        default=["none", "resumption"],
        choices=["none", "resumption"],
    )
    parser.add_argument(
        "--levels", type=int, nargs="+", default=DEFAULT_LEVELS
    )
    parser.add_argument("--out", type=Path, default=OUT_PATH)
    args = parser.parse_args()

    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit(
            "FATAL: openssl tidak ditemukan. Jalankan source env.sh dulu."
        )

    if not RESULTS_CSV.exists():
        raise SystemExit(
            f"FATAL: {RESULTS_CSV} tidak ditemukan. Jalankan consolidate_results.py dulu."
        )

    cores = os.cpu_count() or 1
    rows = []
    for algo in args.algos:
        for mitigation in args.mitigations:
            print(f"\n=== {algo} / mitigation={mitigation} ===")
            wait_for_clean_sockets()
            time.sleep(5)  # jeda tambahan sebagai margin keamanan
            est = estimate_from_results(algo, mitigation, cores)
            measured, cpu_at_sat = measure_capacity(
                openssl, algo, mitigation, args.levels
            )
            algo_name, _, _ = DISPLAY[algo]
            rows.append(
                {
                    "algorithm": algo_name,
                    "mitigation": mitigation,
                    "server_cores": cores,
                    "est_max_concurrent": round(est, 2)
                    if est is not None
                    else "",
                    "measured_max_concurrent": measured,
                    "cpu_percent_at_saturation": round(cpu_at_sat, 2),
                }
            )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "algorithm",
                "mitigation",
                "server_cores",
                "est_max_concurrent",
                "measured_max_concurrent",
                "cpu_percent_at_saturation",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSelesai. {len(rows)} baris ditulis ke {args.out}")


if __name__ == "__main__":
    main()
