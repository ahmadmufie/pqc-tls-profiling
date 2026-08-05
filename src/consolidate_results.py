#!/usr/bin/env python3
"""
consolidate_results.py — FR-8: Gabungkan seluruh hasil pengukuran M2-M4
menjadi satu data/results.csv dengan skema tunggal sesuai PRD Bagian 8.

Sumber data:
  - data/raw/x509_component_sizes.csv   (M2, x509_inspect.py)
      Skema BEDA -- per komponen struktur sertifikat, bukan per-trial
      pengukuran waktu. Dipetakan sebagai operation "x509_inspect",
      trial_number=1 (ukuran struktural X.509 deterministik untuk
      sertifikat yang sama, bukan hasil N-trial berulang seperti timing),
      file_size_bytes=total_bytes. Kolom timing/handshake dikosongkan
      karena memang tidak relevan untuk jenis operasi ini.
  - data/raw/bench_crypto.csv           (M2, bench_crypto.py)
  - data/raw/tls_handshake_bench.csv    (M3, tls_client_bench.py)
  - data/raw/chain_pruning_bench.csv    (M4, mitigation_pruning.py)
      Ketiga file di atas SUDAH PERSIS berskema results.csv -- digabung
      langsung tanpa transformasi.

Catatan skema: kolom kosong pada beberapa baris (mis. handshake_bytes_total
kosong untuk operation=keygen/sign/verify/x509_inspect, chain_length kosong
untuk keygen/sign/verify) BUKAN pelanggaran acceptance criteria PRD --
kolom itu memang tidak berlaku untuk jenis operasi tersebut. Yang wajib
selalu terisi: run_id, algorithm, algorithm_family, security_level,
cert_level, operation, trial_number, timestamp.

Skema akhir data/results.csv (PRD Bagian 8):
  run_id, algorithm, algorithm_family, security_level, cert_level,
  operation, trial_number, time_ms, cpu_time_ms, peak_memory_kb,
  file_size_bytes, chain_length, mitigation, handshake_bytes_total,
  timestamp
"""

import csv
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = PROJECT_ROOT / "data" / "results.csv"

FIELDNAMES = [
    "run_id",
    "algorithm",
    "algorithm_family",
    "security_level",
    "cert_level",
    "operation",
    "trial_number",
    "time_ms",
    "cpu_time_ms",
    "peak_memory_kb",
    "file_size_bytes",
    "chain_length",
    "mitigation",
    "handshake_bytes_total",
    "timestamp",
]

# Sama persis dengan DISPLAY di tls_client_bench.py -- didefinisikan ulang
# (bukan di-import) supaya skrip ini berdiri sendiri, tidak memicu efek
# samping (mis. prompt sudo) dari modul TLS benchmark saat diimpor.
DISPLAY = {
    "mldsa44": ("ML-DSA-44", "ML-DSA", "2"),
    "mldsa65": ("ML-DSA-65", "ML-DSA", "3"),
    "mldsa87": ("ML-DSA-87", "ML-DSA", "5"),
    "ecc-p256": ("ECDSA-P256", "ECC", "~128-bit"),
    "ecc-p384": ("ECDSA-P384", "ECC", "~192-bit"),
    "ecc-p521": ("ECDSA-P521", "ECC", "~256-bit"),
}


def load_direct_schema_csv(path: Path) -> list[dict]:
    """Baca CSV yang sudah persis berskema results.csv."""
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        return [{k: row.get(k, "") for k in FIELDNAMES} for row in reader]


def load_x509_component_sizes(path: Path) -> list[dict]:
    """Petakan x509_component_sizes.csv ke skema results.csv sebagai
    operation 'x509_inspect'."""
    run_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    rows = []
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            code = row["algorithm_code"]
            if code not in DISPLAY:
                raise SystemExit(f"FATAL: algorithm_code tidak dikenal: {code!r}")
            algo_name, family, sec_level = DISPLAY[code]
            rows.append(
                {
                    "run_id": run_id,
                    "algorithm": algo_name,
                    "algorithm_family": family,
                    "security_level": sec_level,
                    "cert_level": row["cert_level"],
                    "operation": "x509_inspect",
                    "trial_number": 1,
                    "time_ms": "",
                    "cpu_time_ms": "",
                    "peak_memory_kb": "",
                    "file_size_bytes": row["total_bytes"],
                    "chain_length": "",
                    "mitigation": "none",
                    "handshake_bytes_total": "",
                    "timestamp": timestamp,
                }
            )
    return rows


def main() -> None:
    sources = [
        ("data/raw/x509_component_sizes.csv", load_x509_component_sizes),
        ("data/raw/bench_crypto.csv", load_direct_schema_csv),
        ("data/raw/tls_handshake_bench.csv", load_direct_schema_csv),
        ("data/raw/chain_pruning_bench.csv", load_direct_schema_csv),
    ]
    all_rows: list[dict] = []
    for rel_path, loader in sources:
        path = PROJECT_ROOT / rel_path
        if not path.exists():
            raise SystemExit(f"FATAL: file sumber tidak ditemukan: {path}")
        rows = loader(path)
        print(f"  {rel_path}: {len(rows)} baris")
        all_rows.extend(rows)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\nSelesai. {len(all_rows)} baris ditulis ke {OUT_PATH}")


if __name__ == "__main__":
    main()
