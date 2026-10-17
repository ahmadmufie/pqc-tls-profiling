#!/usr/bin/env python3
"""
capacity_model.py — M5/FR-9: Estimasi & validasi empiris kapasitas server
(jumlah koneksi TLS 1.3 konkuren maksimum) per kombinasi algoritma x
mitigasi.

Scope asli M5: 6 algoritma x 2 kondisi mitigasi (none = baseline penuh,
resumption = PSK-based session resumption).

PERLUASAN (pasca-M5, untuk menjawab judul "profil adaptif" secara lebih
solid): menambahkan chain pruning sebagai dimensi mitigasi KETIGA yang
diuji kapasitasnya, dan kombinasi resumption+chain_pruning sebagai yang
KEEMPAT. Chain pruning di sini memakai mode "no-root" (BUKAN
"leaf-only") karena "no-root" adalah pruning yang benar-benar terjadi di
wire, sedangkan "leaf-only" butuh simulasi cache client ala RFC 7924
(lihat mitigation_pruning.py) yang tidak representatif untuk klaim
KAPASITAS riil -- boleh dipakai untuk FR-7 (ukuran/byte), tapi tidak
untuk FR-9 (kapasitas).

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

PERBAIKAN METODOLOGI (audit 2026-08-10): sebelumnya tiap level beban
HANYA diuji SATU KALI dan keputusan jenuh langsung final -- TIDAK ADA
retry/konfirmasi sama sekali (lebih rentan noise daripada versi lama
staged_adaptive_capacity.py yang setidaknya sudah punya 1x retry).
Sekarang tiap level diuji TOTAL_ATTEMPTS=3 kali dan keputusan jenuh/tidak
dipakai lewat VOTING MAYORITAS (lihat test_level_majority), konsisten
dengan perbaikan yang sama di staged_adaptive_capacity.py.

PERBAIKAN #2 (audit 2026-08-10): kolom latensi TIDAK PERNAH ditulis ke
CSV output sebelumnya walau latensi adalah SINYAL UTAMA kriteria jenuh
(CPU% cuma diagnostik pendukung -- lihat CATATAN METODOLOGI PENTING #1
di atas). Ditambahkan kolom avg_latency_ms_at_saturation supaya kriteria
jenuh bisa diverifikasi langsung dari data, bukan cuma dari log terminal.

PERBAIKAN #3 (audit 2026-08-10): ditemukan lewat perbandingan data nyata
antar-run -- measured_max_concurrent untuk mitigasi "none" TIDAK
reproducible antar-run (mis. 1200 di satu run, 5000 di run lain untuk
algoritma & level yang identik), sementara mitigasi "resumption" selalu
konsisten. Akar masalah: wait_for_clean_sockets() dulu HANYA dipanggil
sekali di awal tiap kombinasi algoritma+mitigasi, BUKAN di antara level
beban atau di antara percobaan voting dalam level yang sama -- di
antaranya cuma time.sleep(1) polos. Socket TIME_WAIT dari level/percobaan
sebelumnya bisa menumpuk progresif sepanjang satu sweep (terutama untuk
"none" yang sweep-nya panjang/berat), mencemari latensi level berikutnya
dengan noise yang tidak berhubungan dengan kapasitas kriptografi asli.
Sekarang wait_for_clean_sockets() juga dipanggil di antara level dan di
antara percobaan voting (dibatasi waktu tunggunya) supaya tiap pengukuran
mulai dari kondisi socket host yang bersih.

Output: data/capacity_profile.csv
   algorithm, mitigation, server_cores, est_max_concurrent,
   measured_max_concurrent, cpu_percent_at_saturation,
   avg_latency_ms_at_saturation
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
    _register_cleanup,
    do_priming_connection,
    start_server,
    stop_server,
)
from mitigation_pruning import CHAIN_MODES, resolve_cafile

RESULTS_CSV = PROJECT_ROOT / "data" / "results.csv"
OUT_PATH = PROJECT_ROOT / "data" / "capacity_profile.csv"
DEFAULT_LEVELS = [5, 10, 20, 40, 80, 120, 160, 200]
SATURATION_CPU_PCT = 90.0  # diagnostik sekunder, bukan pemicu utama
LATENCY_SATURATION_FACTOR = 3.0  # level dianggap jenuh jika latensi >= 3x baseline
SAMPLER_INTERVAL_S = 0.25

# PERBAIKAN METODOLOGI (audit 2026-08-10, menyusul temuan bug yang sama di
# staged_adaptive_capacity.py): sebelumnya setiap level HANYA diuji SATU
# KALI lalu keputusan jenuh/tidak langsung final -- tidak ada perlindungan
# sama sekali terhadap noise sesaat (jitter OS/WSL), jadi satu lonjakan
# latensi kebetulan bisa menghentikan sweep terlalu dini (measured_max_
# concurrent dilaporkan lebih RENDAH dari kapasitas asli), atau sebaliknya
# satu sampel kebetulan lancar bisa melewatkan jenuh yang sungguhan.
# Sekarang tiap level diuji TOTAL_ATTEMPTS kali dan keputusan jenuh/tidak
# dipakai lewat VOTING MAYORITAS (simetris ke dua arah noise) -- skema
# yang sama dipakai di staged_adaptive_capacity.py.
TOTAL_ATTEMPTS = 3  # jumlah percobaan per level untuk voting mayoritas (ganjil)
MAJORITY_THRESHOLD = (TOTAL_ATTEMPTS // 2) + 1  # jumlah suara "jenuh" minimum agar level dianggap benar-benar saturasi

# Pemetaan nama mitigasi (kolom CSV & --mitigations) -> (chain_mode server,
# pakai resumption atau tidak). "full" = kirim leaf+intermediate+root
# seperti biasa; "no-root" = chain pruning nyata (server tidak kirim root).
MITIGATION_CONFIG = {
    "none": {"chain_mode": "full", "resumption": False},
    "resumption": {"chain_mode": "full", "resumption": True},
    "chain_pruning": {"chain_mode": "no-root", "resumption": False},
    "resumption+chain_pruning": {"chain_mode": "no-root", "resumption": True},
}


def start_server_with_chain_mode(
    algo: str, chain_mode: str, naccept: int
) -> subprocess.Popen:
    """Sama seperti start_server() di tls_client_bench.py, tapi bisa
    memaksa chain_mode tertentu (dipakai untuk uji kapasitas dengan chain
    pruning aktif)."""
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


def estimate_from_results(
    algo_code: str, mitigation: str, cores: int
) -> float | None:
    """Hitung est_max_concurrent dari rata-rata cpu_time_ms di results.csv.
    Untuk mitigasi berbasis chain pruning, data cpu_time_ms datang dari
    mitigation_pruning.py (mitigation="pruning" di results.csv), disaring
    lebih lanjut lewat chain_length supaya no-root tidak tercampur dengan
    leaf-only. Untuk resumption+chain_pruning belum pernah diukur cpu_time
    gabungannya (di luar scope mitigation_pruning.py) -- estimasi teoretis
    akan kosong (None) untuk kombinasi ini, itu batasan yang diketahui,
    bukan bug; measured_max_concurrent tetap valid karena diukur langsung."""
    algo_name, _, _ = DISPLAY[algo_code]
    cfg = MITIGATION_CONFIG[mitigation]
    operation = "handshake_resumed" if cfg["resumption"] else "handshake_full"
    if cfg["chain_mode"] == "full":
        mitigation_col = "session_resumption" if cfg["resumption"] else "none"
        chain_length_filter = None
    else:
        mitigation_col = "pruning"
        chain_length_filter = str(CHAIN_MODES[cfg["chain_mode"]])
    cpu_times = []
    with RESULTS_CSV.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if (
                row["algorithm"] == algo_name
                and row["operation"] == operation
                and row["mitigation"] == mitigation_col
                and (
                    chain_length_filter is None
                    or row.get("chain_length") == chain_length_filter
                )
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


def test_level_majority(
    openssl: str,
    port: int,
    cafile: Path,
    session_file: Path | None,
    level: int,
    baseline_latency: float | None,
) -> tuple[bool, float, float, float]:
    """Uji satu level TOTAL_ATTEMPTS kali dan putuskan jenuh/tidak lewat
    VOTING MAYORITAS -- lihat catatan PERBAIKAN METODOLOGI di atas
    TOTAL_ATTEMPTS/MAJORITY_THRESHOLD. Kembalikan (is_saturated,
    success_rate, avg_cpu, avg_latency) dgn success_rate/avg_cpu/
    avg_latency dirata-ratakan dari seluruh percobaan supaya lebih tahan
    jitter sesaat dibanding satu sampel tunggal."""
    attempts: list[tuple[bool, float, float, float]] = []
    for attempt in range(1, TOTAL_ATTEMPTS + 1):
        success_rate, avg_cpu, avg_latency = run_load_level(
            openssl, port, cafile, session_file, level
        )
        is_sat = success_rate < 1.0 or (
            baseline_latency is not None
            and avg_latency >= LATENCY_SATURATION_FACTOR * baseline_latency
        )
        attempts.append((is_sat, success_rate, avg_cpu, avg_latency))
        tag = "saturated" if is_sat else "ok"
        print(
            f"    concurrency={level:4d}  percobaan {attempt}/{TOTAL_ATTEMPTS}  "
            f"success_rate={success_rate*100:5.1f}%  avg_cpu={avg_cpu:5.1f}%  "
            f"avg_latency={avg_latency:7.1f}ms  -> {tag}"
        )
        if attempt < TOTAL_ATTEMPTS:
            # PERBAIKAN #3 (audit 2026-08-10): dulu cuma time.sleep(1) di sini.
            # Socket TIME_WAIT dari percobaan sebelumnya (di level yang sama)
            # bisa belum reda, mencemari percobaan berikutnya dengan latensi
            # semu -- terutama untuk mitigasi "none" (full handshake, paling
            # berat). Sekarang aktif menunggu sampai TIME_WAIT reda (dibatasi
            # waktu tunggunya supaya tidak memperlambat pengujian ringan).
            wait_for_clean_sockets(max_wait_s=30.0, poll_interval_s=2.0, threshold=100)
    sat_votes = sum(1 for a in attempts if a[0])
    final_is_sat = sat_votes >= MAJORITY_THRESHOLD
    avg_sr = statistics.mean(a[1] for a in attempts)
    avg_cpu_all = statistics.mean(a[2] for a in attempts)
    avg_lat_all = statistics.mean(a[3] for a in attempts)
    print(
        f"    concurrency={level:4d}  -> VOTE {sat_votes}/{TOTAL_ATTEMPTS} saturated "
        f"=> {'saturated' if final_is_sat else 'ok'} (avg lat={avg_lat_all:7.1f}ms)"
    )
    return final_is_sat, avg_sr, avg_cpu_all, avg_lat_all


def measure_capacity(
    openssl: str, algo_code: str, mitigation: str, levels: list[int]
) -> tuple[int, float, float]:
    """Naikkan level konkurensi bertahap sampai saturasi. Kembalikan
    (measured_max_concurrent, cpu_percent_at_saturation,
    avg_latency_ms_at_best_level). Latensi dikembalikan juga karena itu
    SINYAL UTAMA kriteria jenuh (lihat LATENCY_SATURATION_FACTOR) --
    sebelumnya nilai ini dihitung tapi dibuang, tidak pernah tercatat ke
    CSV output, sehingga tidak bisa diverifikasi manual dari data saja."""
    cfg = MITIGATION_CONFIG[mitigation]
    chain_mode = cfg["chain_mode"]
    use_resumption = cfg["resumption"]
    port = PORTS[algo_code]
    cafile = resolve_cafile(algo_code, chain_mode)
    total_conns_needed = (sum(levels) + (1 if use_resumption else 0) + 5) * TOTAL_ATTEMPTS
    server = start_server_with_chain_mode(algo_code, chain_mode, total_conns_needed)
    time.sleep(1)
    session_file = None
    try:
        if use_resumption:
            session_file = TMP_DIR / algo_code / "session_capacity.pem"
            session_file.parent.mkdir(parents=True, exist_ok=True)
            if session_file.exists():
                session_file.unlink()
            do_priming_connection(openssl, port, cafile, session_file)
            if not session_file.exists():
                raise SystemExit(
                    f"FATAL: priming resumption gagal untuk {algo_code} (capacity test)"
                )
        best_level = 0
        cpu_at_best = 0.0
        latency_at_best = 0.0
        baseline_latency = None
        for level in levels:
            is_saturated, success_rate, avg_cpu, avg_latency = test_level_majority(
                openssl, port, cafile, session_file, level, baseline_latency
            )
            if baseline_latency is None and not is_saturated:
                baseline_latency = avg_latency
            if not is_saturated:
                best_level = level
                cpu_at_best = avg_cpu
                latency_at_best = avg_latency
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
                    latency_at_best = avg_latency
                break
            # PERBAIKAN #3 (audit 2026-08-10): dulu cuma time.sleep(1) di sini,
            # sehingga TIME_WAIT dari level ini bisa menumpuk progresif ke
            # level berikutnya dalam satu sweep -- terutama untuk mitigasi
            # "none" yang sweep-nya panjang (banyak level sebelum jenuh).
            # Ini penyebab utama measured_max_concurrent "none" tidak
            # reproducible antar-run (lihat audit ketidakkonsistenan
            # kapasitas-penuh vs kapasitas-pruning). Sekarang aktif menunggu
            # TIME_WAIT reda sebelum lanjut ke level berikutnya.
            wait_for_clean_sockets(max_wait_s=45.0, poll_interval_s=2.0, threshold=100)
        return best_level, cpu_at_best, latency_at_best
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
        choices=list(MITIGATION_CONFIG.keys()),
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
            measured, cpu_at_sat, latency_at_sat = measure_capacity(
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
                    "avg_latency_ms_at_saturation": round(latency_at_sat, 2),
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
                "avg_latency_ms_at_saturation",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSelesai. {len(rows)} baris ditulis ke {args.out}")


if __name__ == "__main__":
    main()
