#!/usr/bin/env python3
"""
report_summary.py — Cetak ringkasan hasil skripsi dari data yang SUDAH ADA
(data/results.csv dan data/capacity_profile.csv). Tidak menjalankan ulang
apa pun -- aman dan instan untuk dipakai saat sesi tanya-jawab sidang,
sebagai jaring pengaman kalau demo live tidak memungkinkan.
"""

import csv
import statistics
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_CSV = PROJECT_ROOT / "data" / "results.csv"
CAPACITY_CSV = PROJECT_ROOT / "data" / "capacity_profile.csv"

ALGO_ORDER = [
    "ECDSA-P256",
    "ECDSA-P384",
    "ECDSA-P521",
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
]


def load_results():
    with RESULTS_CSV.open(newline="") as f:
        return list(csv.DictReader(f))


def load_capacity():
    with CAPACITY_CSV.open(newline="") as f:
        return list(csv.DictReader(f))


def section(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def fmt(v, nd=1):
    try:
        return f"{float(v):,.{nd}f}"
    except (TypeError, ValueError):
        return "-"


def print_table(headers, rows):
    widths = [
        max(len(str(h)), *(len(str(r[i])) for r in rows))
        for i, h in enumerate(headers)
    ]
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(line)
    print("-" * len(line))
    for r in rows:
        print("  ".join(str(c).ljust(w) for c, w in zip(r, widths)))


def summarize_x509(rows):
    section("FR-3: Ukuran sertifikat (x509_inspect) -- root cert per algoritma")
    by_algo = {}
    for r in rows:
        if r["operation"] == "x509_inspect" and r.get("file_size_bytes"):
            by_algo.setdefault(r["algorithm"], []).append(
                float(r["file_size_bytes"])
            )
    table = []
    for algo in ALGO_ORDER:
        if algo in by_algo:
            table.append(
                [algo, fmt(statistics.mean(by_algo[algo]), 0) + " bytes"]
            )
    print_table(["Algoritma", "Ukuran (root cert)"], table)


def summarize_crypto(rows):
    section("FR-4: Rata-rata waktu keygen/sign/verify (ms)")
    by_algo_op = {}
    for r in rows:
        if r["operation"] in ("keygen", "sign", "verify") and r.get("time_ms"):
            key = (r["algorithm"], r["operation"])
            by_algo_op.setdefault(key, []).append(float(r["time_ms"]))
    table = []
    for algo in ALGO_ORDER:
        row = [algo]
        for op in ("keygen", "sign", "verify"):
            vals = by_algo_op.get((algo, op))
            row.append(fmt(statistics.mean(vals)) if vals else "-")
        table.append(row)
    print_table(
        ["Algoritma", "keygen (ms)", "sign (ms)", "verify (ms)"], table
    )


def summarize_handshake(rows):
    section("FR-5/FR-6: Handshake full vs resumed -- rata-rata byte on-wire")
    by_algo_op = {}
    for r in rows:
        if r["operation"] in (
            "handshake_full",
            "handshake_resumed",
        ) and r.get("handshake_bytes_total"):
            key = (r["algorithm"], r["operation"])
            by_algo_op.setdefault(key, []).append(
                float(r["handshake_bytes_total"])
            )
    table = []
    for algo in ALGO_ORDER:
        full = by_algo_op.get((algo, "handshake_full"))
        resumed = by_algo_op.get((algo, "handshake_resumed"))
        if full or resumed:
            f_val = statistics.mean(full) if full else None
            r_val = statistics.mean(resumed) if resumed else None
            reduction = (
                f"{(1 - r_val / f_val) * 100:.1f}%"
                if (f_val and r_val)
                else "-"
            )
            table.append(
                [
                    algo,
                    fmt(f_val, 0) if f_val else "-",
                    fmt(r_val, 0) if r_val else "-",
                    reduction,
                ]
            )
    print_table(
        ["Algoritma", "Full (bytes)", "Resumed (bytes)", "Reduksi"], table
    )


def summarize_pruning(rows):
    section("FR-7: Chain pruning -- rata-rata byte on-wire per mode")
    by_algo_mode = {}
    for r in rows:
        if (
            r["operation"] == "handshake_full"
            and r.get("chain_length")
            and r.get("handshake_bytes_total")
        ):
            key = (r["algorithm"], r["chain_length"])
            by_algo_mode.setdefault(key, []).append(
                float(r["handshake_bytes_total"])
            )
    table = []
    for algo in ALGO_ORDER:
        row = [algo]
        for chain_len in ("3", "2", "1"):
            vals = by_algo_mode.get((algo, chain_len))
            row.append(fmt(statistics.mean(vals), 0) if vals else "-")
        table.append(row)
    print_table(
        [
            "Algoritma",
            "full (chain=3)",
            "no-root (chain=2)",
            "leaf-only (chain=1)",
        ],
        table,
    )


def summarize_capacity(rows):
    section("FR-9: Kapasitas server terukur (measured_max_concurrent)")
    table = []
    for algo in ALGO_ORDER:
        none_row = next(
            (
                r
                for r in rows
                if r["algorithm"] == algo and r["mitigation"] == "none"
            ),
            None,
        )
        res_row = next(
            (
                r
                for r in rows
                if r["algorithm"] == algo and r["mitigation"] == "resumption"
            ),
            None,
        )
        if none_row or res_row:
            table.append(
                [
                    algo,
                    none_row["measured_max_concurrent"] if none_row else "-",
                    res_row["measured_max_concurrent"] if res_row else "-",
                    res_row["est_max_concurrent"] if res_row else "-",
                ]
            )
    print_table(
        ["Algoritma", "Tanpa mitigasi", "Dengan resumption", "Est. teoretis"],
        table,
    )


def main():
    if not RESULTS_CSV.exists():
        raise SystemExit(
            f"FATAL: {RESULTS_CSV} tidak ditemukan. Jalankan consolidate_results.py dulu."
        )

    results = load_results()
    extra_msg = (
        " dan data/capacity_profile.csv" if CAPACITY_CSV.exists() else ""
    )
    print(
        f"RINGKASAN HASIL SKRIPSI -- dibaca langsung dari data/results.csv{extra_msg}"
    )

    summarize_x509(results)
    summarize_crypto(results)
    summarize_handshake(results)
    summarize_pruning(results)

    if CAPACITY_CSV.exists():
        summarize_capacity(load_capacity())
    else:
        section("FR-9: Kapasitas server")
        print("data/capacity_profile.csv belum ada.")

    print("\n" + "=" * 78)
    print("Selesai.")


if __name__ == "__main__":
    main()
