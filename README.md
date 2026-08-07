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

Jalankan `make help` untuk daftar lengkap perintah beserta variabel opsional
(`PAKSA=1`, `HANYA=<algo>`, `CEPAT=1`, `RINCI=1`).

## Struktur direktori

```
pki/{mldsa44,mldsa65,mldsa87,ecc-p256,ecc-p384,ecc-p521}/   hierarki sertifikat per algoritma
src/                          semua skrip pipeline
data/raw/                     CSV mentah per FR (gitignored)
data/results.csv              dataset resmi terkonsolidasi (FR-8)
data/capacity_profile.csv     hasil load test kapasitas (FR-9)
docs/                         dokumen pendukung
```

## Peringatan penting

- **Jangan** menjalankan target tanpa `CEPAT=1` / `--out /tmp/...` kalau hanya
  ingin demo — itu akan menimpa dataset resmi di `data/`.
- `data/raw/` di-gitignore; `data/results.csv` dan `data/capacity_profile.csv`
  di-commit karena itu dataset resmi laporan.

Lihat `DOCS.md` untuk pemetaan FR/Milestone, penjelasan temuan, dan
troubleshooting.
