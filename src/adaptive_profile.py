#!/usr/bin/env python3
"""
adaptive_profile.py -- Menyusun REKOMENDASI PROFIL ADAPTIF dari
data/capacity_profile.csv (M5/FR-9), sesuai PRD Bagian 3.1 poin 7:
"estimasi jumlah koneksi konkuren yang bisa ditangani server per
kombinasi algoritma+mitigasi, SEBAGAI DASAR REKOMENDASI 'TLS 1.3
profil adaptif'".

capacity_profile.csv hanya berisi DATA MENTAH (12 baris ukur). Skrip ini
mengubahnya jadi TABEL KEPUTUSAN EKSPLISIT: untuk setiap ambang beban
konkuren, algoritma+mitigasi mana yang direkomendasikan.

KEBIJAKAN ADAPTIF (harus bisa dipertanggungjawabkan saat sidang):
  1. PRIORITASKAN keamanan pasca-kuantum (ML-DSA) selama kapasitas
     terukurnya mencukupi beban yang diperkirakan -- ini konsisten
     dengan tujuan riset (migrasi ke PQC), bukan sekadar "pilih yang
     kapasitasnya paling besar" (yang akan selalu memenangkan ECDSA
     dan meniadakan poin skripsi).
  2. Di antara level keamanan ML-DSA, pilih yang PALING RINGAN
     (ML-DSA-44) dulu; naik ke ML-DSA-65/87 hanya kalau memang
     dibutuhkan level keamanan lebih tinggi (bukan dimodelkan di sini,
     jadi urutan preferensi 44 -> 65 -> 87 dipakai sebagai default).
  3. Di dalam satu algoritma, coba TANPA mitigasi dulu (lebih sederhana
     operasionalnya); pakai resumption hanya kalau tanpa mitigasi tidak
     cukup kapasitasnya.
  4. HANYA jatuh ke ECDSA (klasik, rentan kuantum) kalau TIDAK ADA
     kombinasi ML-DSA yang cukup kapasitasnya untuk beban tersebut.

Output: data/adaptive_profile.csv + tabel ringkas ke stdout.
"""

import csv
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
IN_PATH = PROJECT_ROOT / "data" / "capacity_profile.csv"
OUT_PATH = PROJECT_ROOT / "data" / "adaptive_profile.csv"

# Urutan preferensi (paling disukai lebih dulu). Dipilih HANYA jika
# measured_max_concurrent kombinasi itu >= ambang beban yang diuji.
PREFERENCE_ORDER = [
    ("ML-DSA-44", "none"),
    ("ML-DSA-44", "resumption"),
    ("ML-DSA-65", "none"),
    ("ML-DSA-65", "resumption"),
    ("ML-DSA-87", "none"),
    ("ML-DSA-87", "resumption"),
    ("ECDSA-P256", "none"),
    ("ECDSA-P256", "resumption"),
    ("ECDSA-P384", "none"),
    ("ECDSA-P384", "resumption"),
    ("ECDSA-P521", "none"),
    ("ECDSA-P521", "resumption"),
]

# Baris dengan anomali yang SUDAH DIDOKUMENTASIKAN di DOCS.md (bukan
# ditemukan baru di sini) -- ditandai eksplisit di output supaya tidak
# dipakai sebagai "kebetulan bagus" tanpa disclaimer saat sidang.
KNOWN_ANOMALOUS = {
    ("ML-DSA-65", "resumption"),  # kapasitas terukur turun vs tanpa mitigasi
    ("ECDSA-P384", "resumption"),  # baseline latensi tinggi (anomali P-384/P-521)
    ("ECDSA-P521", "none"),
    ("ECDSA-P521", "resumption"),
}


def load_rows():
    with IN_PATH.open(newline="") as f:
        return list(csv.DictReader(f))


def recommend_for_load(rows, load: int):
    """Pilih kombinasi sesuai PREFERENCE_ORDER yang measured_max_concurrent-nya
    >= load. Kembalikan (algorithm, mitigation, measured, is_anomalous) atau None."""
    by_key = {(r["algorithm"], r["mitigation"]): r for r in rows}
    for algo, mit in PREFERENCE_ORDER:
        row = by_key.get((algo, mit))
        if row is None:
            continue
        measured = int(float(row["measured_max_concurrent"]))
        if measured >= load:
            return algo, mit, measured, (algo, mit) in KNOWN_ANOMALOUS
    return None


def main():
    rows = load_rows()

    # Ambang beban diambil dari nilai measured_max_concurrent unik yang
    # benar-benar muncul di data (bukan angka bulat sembarang), supaya
    # tabel keputusan langsung dapat ditelusuri balik ke baris pengukuran.
    thresholds = sorted({int(float(r["measured_max_concurrent"])) for r in rows})
    # Tambahkan satu ambang di bawah nilai terkecil supaya beban rendah
    # juga punya rekomendasi (bukan hanya ambang yang persis sama dengan
    # hasil ukur).
    load_bands = [1] + thresholds

    out_rows = []
    print(f"{'Beban konkuren >=':>18} | {'Rekomendasi':<28} | {'Kapasitas terukur':>17} | Catatan")
    print("-" * 90)
    for load in load_bands:
        rec = recommend_for_load(rows, load)
        if rec is None:
            print(f"{load:>18} | {'TIDAK ADA yang cukup':<28} | {'-':>17} | Semua kombinasi gagal di beban ini")
            out_rows.append(
                {
                    "min_load_konkuren": load,
                    "algorithm": "",
                    "mitigation": "",
                    "measured_max_concurrent": "",
                    "anomali": "",
                }
            )
            continue
        algo, mit, measured, anomalous = rec
        label = f"{algo} + {mit}"
        note = "** ANOMALI (lihat DOCS.md) **" if anomalous else ""
        print(f"{load:>18} | {label:<28} | {measured:>17} | {note}")
        out_rows.append(
            {
                "min_load_konkuren": load,
                "algorithm": algo,
                "mitigation": mit,
                "measured_max_concurrent": measured,
                "anomali": "ya" if anomalous else "tidak",
            }
        )

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "min_load_konkuren",
                "algorithm",
                "mitigation",
                "measured_max_concurrent",
                "anomali",
            ],
        )
        writer.writeheader()
        writer.writerows(out_rows)
    print(f"\nSelesai. {len(out_rows)} baris ditulis ke {OUT_PATH}")


if __name__ == "__main__":
    main()
