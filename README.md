# PQC-TLS Profiling

Profiling performa TLS 1.3 dengan sertifikat Post-Quantum Cryptography
(ML-DSA-44/65/87) dibandingkan ECC klasik (P-256/P-384/P-521), termasuk
dampak mitigasi (session resumption, chain pruning) terhadap ukuran
handshake dan kapasitas server.

## Prasyarat

- WSL2 (Ubuntu) atau Linux
- OpenSSL 3.5.5 Native menyediakan ML-DSA
- Python 3.10+
- `ulimit -n 8192` untuk pengujian kapasitas (FR-9)

## Instalasi

```bash
bash bootstrap.sh                 # sekali saja: build openssl 3.5.5
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
source env.sh                     # wajib di setiap terminal baru
```

## Verifikasi cepat (tanpa menyentuh data resmi, ~3-5 menit)

```bash
make persiapan     # cek openssl, provider, port, PKI
make demo          # jalankan seluruh pipeline versi mini ke /tmp
make ringkasan     # cetak hasil resmi (data/results.csv, data/capacity_profile.csv)
```

## Reproduksi penuh (menulis ulang dataset resmi, ~30-60+ menit)

```bash
make sertifikat        # FR-1: 6 hierarki PKI
make validasi-rantai   # FR-2
make ukuran-sertifikat # FR-3
make benchmark-crypto  # FR-4
make handshake         # FR-5, FR-6
make mitigasi          # FR-7
make gabung            # FR-8: data/results.csv
make kapasitas-penuh   # FR-9: data/capacity_profile.csv (~18 menit)
make ringkasan
```

```bash
make kapasitas-pruning ALGO=mldsa44   # FR-9 lanjutan: kapasitas dgn chain pruning & kombinasi
make profil-bertahap ALGO=mldsa44     # FR-9 lanjutan: profil adaptif bertahap (temuan utama adaptivitas)
```

Jalankan `make help` untuk daftar lengkap perintah beserta variabel opsional
(`PAKSA=1`, `ALGO=<algo>` untuk target server TLS, `CEPAT=1`, `RINCI=1`).
`HANYA=<algo>` TIDAK berlaku untuk `sertifikat`/`benchmark-crypto` -- kedua skrip itu
selalu memproses ke-6 algoritma sekaligus dan tidak punya opsi filter algoritma
(lihat DOCS.md bagian "Verifikasi Antarmuka CLI").

## Struktur direktori

```
pki/{mldsa44,mldsa65,mldsa87,ecc-p256,ecc-p384,ecc-p521}/   hierarki sertifikat per algoritma
src/                          semua skrip pipeline (lihat daftar di bawah)
data/raw/                     CSV mentah per FR (gitignored)
data/results.csv              dataset resmi terkonsolidasi (FR-8)
data/capacity_profile.csv     kapasitas resmi M5 (FR-9, none+resumption, 12 baris)
data/capacity_profile_pruning_<ALGO>.csv   kapasitas dgn chain_pruning & kombinasi, per algoritma (make kapasitas-pruning ALGO=...)
data/adaptive_capacity_staged_<algo>.csv   profil adaptif bertahap per algoritma (make profil-bertahap, FR-9 lanjutan)
docs/                         dokumen pendukung
```

```
src/
├── gen_pki.py                    FR-1: generate 6 hierarki PKI
├── x509_inspect.py                FR-3: ukuran komponen sertifikat
├── chain_validation.sh             FR-2: validasi rantai kepercayaan
├── bench_crypto.py                FR-4: benchmark keygen/sign/verify
├── tls_server.py / tls_client_bench.py   FR-5, FR-6: handshake TLS 1.3 nyata + resumption
├── mitigation_pruning.py          FR-7: chain pruning
├── consolidate_results.py         FR-8: gabungkan ke data/results.csv
├── capacity_model.py              FR-9: model + load test kapasitas
├── staged_adaptive_capacity.py    FR-9 lanjutan: profil adaptif bertahap (lihat `make profil-bertahap`)
├── report_summary.py              cetak ringkasan dari data resmi
└── diagnose_capacity_env.sh       diagnostik manual (ulimit/port/TIME_WAIT), tanpa target make
```

## Peringatan penting

- **Jangan** menjalankan target tanpa `CEPAT=1` / `--out /tmp/...` kalau hanya
  ingin demo — itu akan menimpa dataset resmi di `data/`.
- `data/raw/` di-gitignore; `data/results.csv` dan `data/capacity_profile.csv`
  di-commit karena itu dataset resmi laporan.

Lihat `DOCS.md` untuk pemetaan FR/Milestone, penjelasan temuan, dan
troubleshooting.
