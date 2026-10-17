#!/usr/bin/env python3
"""
staged_adaptive_capacity.py -- Eksperimen kapasitas bertahap untuk SATU
algoritma (default: ML-DSA-44), sesuai konsep yang diminta:

  1. Mulai dari beban dekat batas AMAN tanpa mitigasi yang sudah diketahui
     dari data/capacity_profile.csv (measured_max_concurrent untuk
     mitigation=none), minus MARGIN (default 100).
  2. Begitu "none" jenuh, uji SATU PERSATU kandidat mitigasi (resumption
     vs chain_pruning) PERSIS pada level jenuh itu. Bandingkan mana yang
     paling menaikkan kapasitas -> itu yang dipakai duluan.
  3. Mitigasi pemenang lalu di-sweep sampai jenuh lagi.
  4. Kalau masih jenuh dan belum dicoba, tambahkan mitigasi kedua
     (gabungan resumption+chain_pruning) dan sweep lagi.
  5. Kalau sudah pakai gabungan dan tetap jenuh -> itu batas akhir profil.

PENTING -- dua perbaikan metodologi setelah ditemukan masalah nyata di
pengujian:

(a) Baseline latensi untuk kriteria jenuh (>= 3x baseline) HARUS diukur
    di level RINGAN TETAP (BASELINE_LEVEL, default 100), bukan dari level
    pertama yang di-sweep. Kalau baseline diambil dari level dekat batas
    lama (mis. 1100), server yang serial sudah mulai antre duluan di
    situ, sehingga baseline jadi kebesaran, ambang 3x jadi longgar, dan
    "jenuh" jadi terdeteksi jauh lebih telat daripada metodologi M5 lama
    (yang baseline-nya dari level 200, jauh lebih ringan).

(b) Batas atas pengujian dibuat PRAKTIS (MAX_LEVEL_CAP = 5000, sama
    dengan cakupan resmi M5 `kapasitas-penuh`), BUKAN dibiarkan naik
    tanpa akhir. Mitigasi seperti `resumption` sangat efisien (melewati
    verifikasi tanda tangan ML-DSA yang mahal) sehingga bisa saja tidak
    pernah "jenuh" walau dinaikkan sampai puluhan ribu koneksi -- itu
    bukan bug, tapi terus menaikkan level tanpa batas tidak realistis
    untuk skripsi (butuh waktu sangat lama & membebani mesin tanpa nilai
    tambah ilmiah). Begitu MAX_LEVEL_CAP tercapai tanpa jenuh, hasil
    dilaporkan apa adanya sebagai "kapasitas >= MAX_LEVEL_CAP", konsisten
    dengan cara data M5 lama melaporkan level tertinggi yang diuji.

(c) PERBAIKAN #2 (audit 2026-08-10): skema konfirmasi jenuh lama
    ASIMETRIS -- satu percobaan ulang yang "ok" langsung membatalkan
    status "saturated" sebelumnya, padahal untuk mengonfirmasi "saturated"
    perlu SEMUA percobaan kompak saturated. Bias ini membuat level di
    zona abu-abu ambang 3x-baseline (latensi mendekati tapi belum pasti
    melewati ambang) cenderung dilaporkan "ok" lebih sering daripada
    seharusnya, dan verdict per-percobaan bisa terlihat tidak konsisten
    urutannya terhadap besar-kecilnya latensi mentah. Diganti dengan
    VOTING MAYORITAS dari TOTAL_ATTEMPTS percobaan (lihat konstanta
    TOTAL_ATTEMPTS/MAJORITY_THRESHOLD) yang simetris ke dua arah noise.
    Baseline latensi (ambang 3x) sekarang juga ditulis eksplisit ke CSV
    output (baris berstage "1_none"/"2_compare"/"4_combined" dengan
    verdict "BASELINE(ambang_3x=...)") supaya bisa diverifikasi manual.

Output: data/adaptive_capacity_staged_<algo>.csv dengan kolom
  stage, mitigation, chain_mode, tested_level, success_rate, avg_cpu_pct,
  avg_latency_ms, verdict. Nilai verdict yang mungkin:
  - "ok" / "saturated": hasil SATU percobaan individual (transparansi).
  - "FINAL_ok" / "FINAL_saturated": hasil akhir voting mayoritas untuk
    level itu -- INI yang dipakai untuk keputusan sweep/bisection.
  - "BASELINE(ambang_3x=...)": baris baseline latensi & ambang jenuh
    yang berlaku untuk mitigasi/stage tsb.

Jalankan dari root project (setelah `source env.sh`):
  python3 src/staged_adaptive_capacity.py --algo mldsa44

Catatan: skrip ini butuh openssl s_server/s_client SUNGGUHAN (tidak bisa
dijalankan di sandbox tanpa openssl OQS-provider). Jalankan di mesin nyata
(WSL) Anda.
"""
from __future__ import annotations

import argparse
import csv
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from capacity_model import (
    MITIGATION_CONFIG,
    PORTS,
    TMP_DIR,
    do_priming_connection,
    run_load_level,
    start_server_with_chain_mode,
    stop_server,
)
from mitigation_pruning import resolve_cafile

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CAPACITY_PROFILE_CSV = PROJECT_ROOT / "data" / "capacity_profile.csv"
LATENCY_SATURATION_FACTOR = 3.0
MARGIN = 100  # mundur dari batas aman lama untuk mulai uji ulang
STEP = 100  # kenaikan level dasar saat sweep mencari titik jenuh

# Batas atas PRAKTIS = sama dengan cakupan resmi M5 (`kapasitas-penuh`
# naik sampai 5000). Bukan target teoritis mutlak -- lihat catatan (b) di
# atas docstring. Kalau sampai level ini masih 'ok', dilaporkan sebagai
# kapasitas >= MAX_LEVEL_CAP, TIDAK dinaikkan lagi.
MAX_LEVEL_CAP = 5000
# Step membesar otomatis kalau level sudah jauh di atas start, supaya
# tidak perlu puluhan iterasi kecil untuk mencapai MAX_LEVEL_CAP.
STEP_GROWTH_THRESHOLD = 1000  # kelipatan kenaikan dari titik mulai
STEP_GROWTH_FACTOR = 5

# Level ringan tetap untuk mengukur baseline latensi -- lihat catatan (a)
# di atas docstring. Dipakai untuk SEMUA mitigasi (none/resumption/
# chain_pruning/gabungan), masing-masing diukur baseline sendiri.
BASELINE_LEVEL = 100

# Satu kali percobaan per level bisa kena noise sesaat (jitter OS/WSL)
# yang membuat latensi melonjak sekali lalu normal lagi, ATAU sebaliknya
# kebetulan lancar sekali padahal levelnya memang sudah jenuh -- kedua
# arah noise ini TERBUKTI nyata terjadi di data (level rendah kadang
# terlihat "saturated" sesaat, level lebih tinggi kadang kebetulan "ok").
#
# PERBAIKAN METODOLOGI (ditemukan lewat audit data hasil M5+): skema lama
# ASIMETRIS -- begitu SATU percobaan ulang menunjukkan "ok", langsung
# dianggap final "ok" (anggap "saturated" sebelumnya cuma noise), padahal
# untuk dianggap "saturated" perlu SEMUA percobaan kompak saturated. Bias
# ini membuat kapasitas cenderung dilaporkan lebih tinggi dari yang
# sebenarnya di level yang pas berada di zona abu-abu ambang 3x-baseline.
# Sekarang dipakai VOTING MAYORITAS dari TOTAL_ATTEMPTS percobaan
# (simetris ke dua arah): level dianggap jenuh HANYA kalau mayoritas
# percobaan menunjukkan saturated.
TOTAL_ATTEMPTS = 3  # jumlah percobaan per level untuk voting mayoritas (ganjil)
MAJORITY_THRESHOLD = (TOTAL_ATTEMPTS // 2) + 1  # jumlah suara "saturated" minimum agar dianggap jenuh sungguhan

# Kalau level pertama yang di-sweep (start_level) LANGSUNG saturated,
# jangan langsung menyerah ke titik sembarang -- turun setengah-setengah
# (bisection) dari titik itu untuk mencari kira-kira di mana "none"
# sungguhan mulai jenuh, minimal MIN_BISECT_LEVEL.
MIN_BISECT_LEVEL = 50


def known_ceiling_none(algo_code: str) -> int:
    """Ambil measured_max_concurrent untuk mitigation=none dari
    data/capacity_profile.csv (data resmi M5) sebagai titik awal."""
    with CAPACITY_PROFILE_CSV.open(newline="") as f:
        for row in csv.DictReader(f):
            if row["algorithm"].lower().replace("-", "") == algo_code.replace(
                "-", ""
            ) and row["mitigation"] == "none":
                return int(float(row["measured_max_concurrent"]))
    raise SystemExit(
        f"Tidak ada baris mitigation=none untuk {algo_code} di {CAPACITY_PROFILE_CSV}"
    )


def run_one_level_raw(
    openssl: str, algo_code: str, mitigation: str, level: int
) -> tuple[float, float, float]:
    """Start server dgn konfigurasi mitigasi, jalankan satu level beban,
    kembalikan (success_rate, avg_cpu, avg_latency) TANPA menilai jenuh."""
    cfg = MITIGATION_CONFIG[mitigation]
    chain_mode = cfg["chain_mode"]
    use_resumption = cfg["resumption"]
    port = PORTS[algo_code]
    cafile = resolve_cafile(algo_code, chain_mode)
    total_conns_needed = level + (1 if use_resumption else 0) + 5
    server = start_server_with_chain_mode(algo_code, chain_mode, total_conns_needed)
    time.sleep(1)
    session_file = None
    try:
        if use_resumption:
            session_file = TMP_DIR / algo_code / "session_staged.pem"
            session_file.parent.mkdir(parents=True, exist_ok=True)
            if session_file.exists():
                session_file.unlink()
            do_priming_connection(openssl, port, cafile, session_file)
            if not session_file.exists():
                raise SystemExit(
                    f"FATAL: priming resumption gagal untuk {algo_code}"
                )
        return run_load_level(openssl, port, cafile, session_file, level)
    finally:
        stop_server(server)
        time.sleep(0.5)


def measure_baseline(
    openssl: str, algo_code: str, mitigation: str, rows: list[dict] | None = None, stage: str = "0_baseline"
) -> float:
    """Ukur baseline latensi di level RINGAN tetap (BASELINE_LEVEL), jadi
    acuan kriteria jenuh (>= 3x baseline) yang sebanding dgn data M5.
    Kalau `rows` diberikan, baseline ini JUGA dicatat ke CSV output supaya
    transparan (sebelumnya ambang 3x-baseline ini tidak pernah terlihat
    di data, sehingga sulit diverifikasi kenapa suatu level dianggap
    jenuh)."""
    sr, cpu, lat = run_one_level_raw(openssl, algo_code, mitigation, BASELINE_LEVEL)
    print(
        f"[baseline]  {mitigation:28s} level={BASELINE_LEVEL:5d} "
        f"success={sr*100:5.1f}% cpu={cpu:5.1f}% lat={lat:7.1f}ms (acuan 3x = {lat * LATENCY_SATURATION_FACTOR:7.1f}ms)"
    )
    if rows is not None:
        rows.append(
            {
                "stage": stage,
                "mitigation": mitigation,
                "chain_mode": MITIGATION_CONFIG[mitigation]["chain_mode"],
                "tested_level": BASELINE_LEVEL,
                "success_rate": round(sr, 4),
                "avg_cpu_pct": round(cpu, 2),
                "avg_latency_ms": round(lat, 2),
                "verdict": f"BASELINE(ambang_3x={round(lat * LATENCY_SATURATION_FACTOR, 2)})",
            }
        )
    return lat


def test_one_level(
    openssl: str,
    algo_code: str,
    mitigation: str,
    level: int,
    baseline_latency: float,
) -> tuple[bool, float, float, float]:
    """Jalankan satu level beban, kembalikan (is_saturated, success_rate,
    avg_cpu, avg_latency). baseline_latency HARUS dari measure_baseline()."""
    success_rate, avg_cpu, avg_latency = run_one_level_raw(
        openssl, algo_code, mitigation, level
    )
    is_saturated = (
        success_rate < 0.99
        or avg_latency >= baseline_latency * LATENCY_SATURATION_FACTOR
    )
    return is_saturated, success_rate, avg_cpu, avg_latency


def test_level_confirmed(
    openssl: str,
    algo_code: str,
    mitigation: str,
    level: int,
    baseline_latency: float,
    rows: list[dict],
    stage: str,
) -> tuple[bool, float, float, float]:
    """Uji satu level TOTAL_ATTEMPTS kali dan putuskan jenuh/tidak lewat
    VOTING MAYORITAS (simetris terhadap noise di kedua arah -- lihat
    catatan di atas TOTAL_ATTEMPTS/MAJORITY_THRESHOLD). Semua percobaan
    individual (termasuk yang jadi minoritas/noise) tetap dicatat ke
    `rows` supaya transparan -- tidak ada data yang disembunyikan.
    Nilai success_rate/avg_cpu_pct/avg_latency_ms yang dikembalikan
    adalah RATA-RATA dari seluruh percobaan, bukan cuma satu sampel,
    supaya lebih tahan terhadap jitter sesaat."""
    attempts: list[tuple[bool, float, float, float]] = []
    for attempt in range(1, TOTAL_ATTEMPTS + 1):
        is_sat, sr, cpu, lat = test_one_level(
            openssl, algo_code, mitigation, level, baseline_latency
        )
        attempts.append((is_sat, sr, cpu, lat))
        tag = "saturated" if is_sat else "ok"
        note = "" if attempt == 1 else f" (percobaan #{attempt})"
        rows.append(
            {
                "stage": stage,
                "mitigation": mitigation,
                "chain_mode": MITIGATION_CONFIG[mitigation]["chain_mode"],
                "tested_level": level,
                "success_rate": round(sr, 4),
                "avg_cpu_pct": round(cpu, 2),
                "avg_latency_ms": round(lat, 2),
                "verdict": tag,
            }
        )
        print(
            f"[{stage}] {mitigation:28s} level={level:5d} "
            f"success={sr*100:5.1f}% cpu={cpu:5.1f}% lat={lat:7.1f}ms "
            f"-> {tag}{note}"
        )
    sat_votes = sum(1 for a in attempts if a[0])
    final_is_sat = sat_votes >= MAJORITY_THRESHOLD
    avg_sr = statistics.mean(a[1] for a in attempts)
    avg_cpu = statistics.mean(a[2] for a in attempts)
    avg_lat = statistics.mean(a[3] for a in attempts)
    final_tag = "saturated" if final_is_sat else "ok"
    rows.append(
        {
            "stage": stage,
            "mitigation": mitigation,
            "chain_mode": MITIGATION_CONFIG[mitigation]["chain_mode"],
            "tested_level": level,
            "success_rate": round(avg_sr, 4),
            "avg_cpu_pct": round(avg_cpu, 2),
            "avg_latency_ms": round(avg_lat, 2),
            "verdict": f"FINAL_{final_tag}",
        }
    )
    print(
        f"[{stage}] {mitigation:28s} level={level:5d} "
        f"-> VOTE {sat_votes}/{TOTAL_ATTEMPTS} saturated "
        f"=> FINAL_{final_tag} (avg lat={avg_lat:7.1f}ms)"
    )
    return final_is_sat, avg_sr, avg_cpu, avg_lat


def sweep_until_saturated(
    openssl: str,
    algo_code: str,
    mitigation: str,
    start_level: int,
    rows: list[dict],
    stage: str,
    baseline_latency: float,
) -> tuple[int, bool]:
    """Naik dari start_level sampai jenuh BENERAN (terkonfirmasi, bukan
    noise sesaat -- lihat test_level_confirmed) atau kena MAX_LEVEL_CAP
    (batas praktis, bukan target teoritis -- lihat catatan (b) di atas
    docstring modul). Kembalikan (last_ok_level, hit_cap). hit_cap=True
    berarti masih 'ok' sampai MAX_LEVEL_CAP -- dilaporkan sebagai
    kapasitas >= MAX_LEVEL_CAP, TIDAK dinaikkan lebih lanjut."""
    last_ok_level = 0
    level = start_level
    step = STEP
    while level <= MAX_LEVEL_CAP:
        is_sat, sr, cpu, lat = test_level_confirmed(
            openssl, algo_code, mitigation, level, baseline_latency, rows, stage
        )
        if is_sat:
            return last_ok_level, False
        last_ok_level = level
        if level - start_level >= STEP_GROWTH_THRESHOLD:
            step = STEP * STEP_GROWTH_FACTOR
        level += step
    return last_ok_level, True


def find_none_saturation_point(
    openssl: str,
    algo_code: str,
    start_level: int,
    baseline_latency: float,
    rows: list[dict],
) -> int:
    """Dipanggil HANYA kalau start_level untuk 'none' langsung 'saturated'
    (terkonfirmasi). Turun setengah-setengah (bisection) mencari kira-kira
    level tertinggi yang masih 'ok', supaya Tahap 2 dibandingkan pada
    level yang representatif -- bukan jatuh sembarang ke level rendah."""
    lo, hi = MIN_BISECT_LEVEL, start_level
    last_ok = 0
    print(
        f"   'none' langsung jenuh di level awal {start_level} -- mencari "
        f"titik jenuh sungguhan lewat bisection turun (batas bawah {lo})..."
    )
    while hi - lo > STEP:
        mid = (lo + hi) // 2
        is_sat, sr, cpu, lat = test_level_confirmed(
            openssl, algo_code, "none", mid, baseline_latency, rows, "1_none_bisect"
        )
        if is_sat:
            hi = mid
        else:
            lo = mid
            last_ok = mid
    return last_ok if last_ok > 0 else lo


def write_rows(rows: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="") as f:
        fieldnames = [
            "stage",
            "mitigation",
            "chain_mode",
            "tested_level",
            "success_rate",
            "avg_cpu_pct",
            "avg_latency_ms",
            "verdict",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--algo", default="mldsa44", choices=list(PORTS.keys()))
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Default: data/adaptive_capacity_staged_<algo>.csv",
    )
    args = parser.parse_args()
    algo_code = args.algo
    out_path = args.out or (
        PROJECT_ROOT / "data" / f"adaptive_capacity_staged_{algo_code}.csv"
    )

    rows: list[dict] = []

    ceiling = known_ceiling_none(algo_code)
    start_level = max(1, ceiling - MARGIN)
    print(
        f"=== TAHAP 1: konfirmasi batas 'none' untuk {algo_code} "
        f"(data lama: {ceiling}, mulai uji dari {start_level}) ==="
    )
    baseline_none = measure_baseline(args.openssl, algo_code, "none", rows, "1_none")
    is_sat_start, sr0, cpu0, lat0 = test_level_confirmed(
        args.openssl, algo_code, "none", start_level, baseline_none, rows, "1_none"
    )
    if is_sat_start:
        # Level pertama yang dicoba SUDAH jenuh (terkonfirmasi, bukan
        # noise) -- jangan lompat sembarang, cari kira-kira titik jenuh
        # sungguhan lewat bisection turun supaya Tahap 2 dibandingkan pada
        # level yang representatif.
        last_ok_none = find_none_saturation_point(
            args.openssl, algo_code, start_level, baseline_none, rows
        )
        hit_cap_none = False
    else:
        last_ok_none, hit_cap_none = sweep_until_saturated(
            args.openssl,
            algo_code,
            "none",
            start_level + STEP,
            rows,
            stage="1_none",
            baseline_latency=baseline_none,
        )
        last_ok_none = max(last_ok_none, start_level)
    if hit_cap_none:
        print(
            f"\n!! 'none' masih 'ok' sampai batas atas praktis "
            f"MAX_LEVEL_CAP={MAX_LEVEL_CAP} (setara cakupan resmi M5).\n"
            f"   Dilaporkan sebagai kapasitas >= {MAX_LEVEL_CAP} untuk 'none' -- "
            f"TIDAK dinaikkan lagi.\n"
            f"   Lanjut ke Tahap 2 memakai level {MAX_LEVEL_CAP} sebagai titik uji."
        )
        saturation_level = MAX_LEVEL_CAP
    else:
        saturation_level = last_ok_none + STEP
        print(
            f"-> 'none' jenuh di sekitar level {saturation_level} "
            f"(bertahan sampai {last_ok_none})"
        )

    print(
        "\n=== TAHAP 2: bandingkan resumption vs chain_pruning PERSIS "
        f"di level jenuh ({saturation_level}) ==="
    )
    candidates = ["resumption", "chain_pruning"]
    candidate_results = {}
    candidate_baselines = {}
    for mit in candidates:
        baseline_mit = measure_baseline(args.openssl, algo_code, mit, rows, "2_compare")
        candidate_baselines[mit] = baseline_mit
        # Pakai test_level_confirmed (bukan test_one_level mentah) supaya
        # perbandingan ini juga terlindung dari noise sesaat -- konsisten
        # dgn Tahap 1/3/4, jangan sampai satu kandidat didiskualifikasi
        # cuma gara-gara satu lonjakan latensi kebetulan.
        is_sat, sr, cpu, lat = test_level_confirmed(
            args.openssl,
            algo_code,
            mit,
            saturation_level,
            baseline_mit,
            rows,
            "2_compare",
        )
        candidate_results[mit] = (is_sat, sr, lat)

    not_saturated = [m for m in candidates if not candidate_results[m][0]]
    if not_saturated:
        winner = min(not_saturated, key=lambda m: candidate_results[m][2])
    else:
        winner = max(candidates, key=lambda m: candidate_results[m][1])
    print(f"-> Mitigasi terpilih untuk dipakai lebih dulu: {winner}")

    print(f"\n=== TAHAP 3: sweep dgn '{winner}' dari level {saturation_level} ===")
    last_ok_winner, hit_cap_winner = sweep_until_saturated(
        args.openssl,
        algo_code,
        winner,
        saturation_level,
        rows,
        stage="3_winner",
        baseline_latency=candidate_baselines[winner],
    )
    if hit_cap_winner:
        print(
            f"\n!! '{winner}' masih 'ok' sampai batas atas praktis "
            f"MAX_LEVEL_CAP={MAX_LEVEL_CAP} (setara cakupan resmi M5).\n"
            f"   Dilaporkan sebagai kapasitas >= {MAX_LEVEL_CAP} -- TIDAK perlu\n"
            f"   dinaikkan lagi maupun dicoba gabungan (mitigasi tunggal ini\n"
            f"   sudah cukup untuk melampaui cakupan pengujian resmi M5)."
        )
        final_mitigation = winner
        final_capacity = last_ok_winner
        capacity_is_lower_bound = True
    else:
        saturation_level_2 = last_ok_winner + STEP
        combined = "resumption+chain_pruning"
        print(
            f"\n=== TAHAP 4: '{winner}' saja jenuh di {saturation_level_2}, "
            f"coba gabungan '{combined}' ==="
        )
        baseline_combined = measure_baseline(args.openssl, algo_code, combined, rows, "4_combined")
        last_ok_combined, hit_cap_combined = sweep_until_saturated(
            args.openssl,
            algo_code,
            combined,
            saturation_level_2,
            rows,
            stage="4_combined",
            baseline_latency=baseline_combined,
        )
        final_mitigation = winner
        final_capacity = last_ok_winner
        capacity_is_lower_bound = hit_cap_combined
        if last_ok_combined > last_ok_winner:
            final_mitigation = combined
            final_capacity = last_ok_combined
        if hit_cap_combined:
            print(
                f"\n!! '{combined}' juga masih 'ok' sampai MAX_LEVEL_CAP="
                f"{MAX_LEVEL_CAP}. Dilaporkan sebagai kapasitas >= {MAX_LEVEL_CAP}."
            )

    bound_note = (
        f" (kapasitas >= {final_capacity}, belum jenuh dalam rentang uji "
        f"sampai MAX_LEVEL_CAP={MAX_LEVEL_CAP})"
        if capacity_is_lower_bound
        else ""
    )
    print(
        f"\n=== HASIL AKHIR: {algo_code} + {final_mitigation} "
        f"-> kapasitas maksimum terukur = {final_capacity} koneksi konkuren{bound_note} ==="
    )

    write_rows(rows, out_path)
    print(f"\nLog lengkap tiap level disimpan ke {out_path}")


if __name__ == "__main__":
    main()
