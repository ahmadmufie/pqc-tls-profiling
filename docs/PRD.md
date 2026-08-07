# PRD — Perancangan Profil TLS 1.3 Pasca-Kuantum Adaptif Berdasarkan Evaluasi Mitigasi Overhead Sertifikat ML-DSA

Status: Draft v2 — disesuaikan untuk alur kerja 
Konteks: Skripsi S1, judul sudah di-ACC pembimbing & kaprodi
Dokumen ini adalah spesifikasi kerja + protokol kolaborasi manual antara mahasiswa (eksekutor di WSL2) dan AI (perancang/reviewer kode lewat chat).

---

## 1. Ringkasan

Membangun sistem eksperimen untuk membandingkan overhead sertifikat X.509 yang ditandatangani dengan ML-DSA (FIPS 204, 3 parameter set) terhadap ECC (baseline klasik), mengukur dampaknya pada handshake TLS 1.3, menerapkan dua mitigasi (session resumption, chain pruning), lalu menyusun profil kapasitas server yang adaptif terhadap pilihan algoritma.

Output akhir: dataset CSV terukur + model/profil yang merekomendasikan kombinasi algoritma+mitigasi berdasarkan beban server.

## 2. Latar Belakang

ML-DSA menghasilkan kunci publik dan signature yang jauh lebih besar dari ECC (30–70x lebih besar per signature). Ini berdampak langsung pada ukuran pesan Certificate di TLS 1.3, yang berpotensi memperbesar jumlah round-trip, waktu handshake, dan konsumsi resource server saat menangani banyak koneksi bersamaan. Penelitian ini mengevaluasi seberapa besar overhead itu secara empiris, lalu menguji apakah session resumption dan chain pruning cukup untuk memitigasinya di skenario produksi.

## 3. Tujuan

### 3.1 Tujuan utama
1. Membangun 6 hierarki PKI homogen (root→intermediate→leaf, satu algoritma per hierarki): ML-DSA-44, ML-DSA-65, ML-DSA-87, ECDSA P-256, P-384, P-521.
2. Menandatangani dan memverifikasi setiap sertifikat pada tiap hierarki.
3. Mengukur waktu, ukuran file, CPU, dan memori untuk setiap operasi (keygen, sign, verify) per algoritma.
4. Menjalankan handshake TLS 1.3 nyata memakai tiap hierarki, diverifikasi lewat browser dan dianalisis lewat capture paket.
5. Menerapkan dan mengukur efek session resumption dan chain pruning terhadap overhead.
6. Mengumpulkan seluruh hasil pengukuran ke CSV dalam format tidy/long.
7. Menyusun profil kapasitas: estimasi jumlah koneksi konkuren yang bisa ditangani server per kombinasi algoritma+mitigasi, sebagai dasar rekomendasi "TLS 1.3 profil adaptif".

### 3.2 Non-tujuan (di luar scope)
- Tidak mengimplementasikan ulang matematika ML-DSA/ECDSA dari nol (lattice/EC arithmetic). Primitif kriptografi memakai OpenSSL sebagai library tervalidasi.
- Tidak membangun implementasi TLS 1.3 dari nol. Memakai OpenSSL/library TLS yang ada sebagai engine handshake; fokus riset ada di lapisan pengukuran, orkestrasi sertifikat, dan mitigasi.
- Tidak menyasar sertifikat hybrid (ECC+ML-DSA campuran). Setiap hierarki murni satu algoritma ("homogen per level").
- Tidak menyasar KEM (ML-KEM) — fokus murni pada signature/certificate authentication, bukan key exchange.

## 4. Batasan Akademis (PENTING)

Penguji secara eksplisit melarang solusi "black-box tools end-to-end" dan meminta unsur reverse engineering.

**Boleh memakai library/tools siap pakai untuk:**
- Operasi kriptografi primitif: keygen, sign, verify (OpenSSL 3.5.x, sudah native mendukung ML-DSA-44/65/87 dan ECDSA).
- TLS record layer / handshake engine bawaan OpenSSL.
- Wireshark/tshark untuk capture paket mentah.

**Wajib diimplementasikan/dianalisis sendiri:**
- Parsing struktur X.509 manual per field (TBSCertificate, AlgorithmIdentifier OID, SubjectPublicKeyInfo, SignatureValue, Extensions) memakai library ASN.1 tingkat rendah, lalu hitung ukuran tiap komponen terpisah.
- Logika pembangunan chain (chain building, trust path, validasi bertingkat) ditulis sendiri sebagai kode.
- Harness pengukuran (timing, CPU, memori) — custom.
- Parsing byte-level handshake TLS dari hasil capture, identifikasi tiap handshake message dan ukurannya sendiri.
- Logika kontrol mitigasi ditulis eksplisit sebagai kode keputusan, disertai penjelasan mekanismenya.
- Model/kalkulasi profil kapasitas — full custom.

## 5. Definisi Istilah & Asumsi

- **Homogen per level**: satu hierarki sertifikat (root, intermediate, leaf) menggunakan satu algoritma+parameter set yang sama di semua level.
- **Algoritma yang diuji**:
  | Kode internal | Algoritma | Kategori keamanan |
  |---|---|---|
  | mldsa44 | ML-DSA-44 | 2 (~128-bit) |
  | mldsa65 | ML-DSA-65 | 3 (~192-bit) |
  | mldsa87 | ML-DSA-87 | 5 (~256-bit) |
  | ecc-p256 | ECDSA P-256 | ~128-bit |
  | ecc-p384 | ECDSA P-384 | ~192-bit |
  | ecc-p521 | ECDSA P-521 | ~256-bit |
- **Trial**: satu kali eksekusi operasi terukur. Minimal 100 trial per kombinasi (algoritma × operasi).
- **Mitigasi "resumption"**: TLS 1.3 PSK-based session resumption via `NewSessionTicket`.
- **Mitigasi "chain pruning"**: variasi jumlah sertifikat yang dikirim server — full chain (3) vs tanpa root (2) vs leaf-only (1).
- Lingkungan uji: server dan client TLS berjalan di WSL2 yang sama (localhost) kecuali dinyatakan lain.

## 6. Arsitektur Sistem

### 6.1 Struktur direktori
```
pqc-tls-profiling/
├── docs/
│   └── PRD.md
├── pki/
│   ├── mldsa44/ {root,intermediate,leaf}.{key,crt}
│   ├── mldsa65/ ...
│   ├── mldsa87/ ...
│   ├── ecc-p256/ ...
│   ├── ecc-p384/ ...
│   └── ecc-p521/ ...
├── src/
│   ├── gen_pki.py
│   ├── x509_inspect.py
│   ├── bench_crypto.py
│   ├── tls_server.py
│   ├── tls_client_bench.py
│   ├── pcap_parse.py
│   ├── mitigation_pruning.py
│   ├── capacity_model.py
│   └── common/
│       ├── metrics.py
│       └── csv_writer.py
├── data/
│   ├── raw/
│   └── results.csv
├── notebooks/
├── bootstrap.sh
└── requirements.txt
```

### 6.2 Modul & tanggung jawab
| Modul | Tanggung jawab | Library inti |
|---|---|---|
| gen_pki.py | Generate 6 hierarki, tiap hierarki 3 level | OpenSSL CLI via subprocess |
| x509_inspect.py | Bedah struktur sertifikat, hitung ukuran per komponen | asn1crypto |
| bench_crypto.py | Ukur waktu/CPU/mem keygen, sign, verify (N trial) | time, resource, subprocess |
| tls_server.py / tls_client_bench.py | Handshake TLS 1.3 nyata, full & resumed | ssl (Python) / openssl s_server/s_client |
| pcap_parse.py | Hitung ukuran & jumlah pesan handshake dari capture | scapy, tshark (capture only) |
| mitigation_pruning.py | Uji 3 varian panjang chain | custom |
| capacity_model.py | Estimasi + validasi empiris kapasitas konkuren | custom, load generator sendiri |

## 7. Functional Requirements

| ID | Requirement |
|---|---|
| FR-1 | Generate root/intermediate/leaf cert untuk 6 algoritma, homogen per hierarki |
| FR-2 | Setiap sertifikat ditandatangani dengan algoritma hierarkinya sendiri |
| FR-3 | Verifikasi rantai kepercayaan penuh (leaf→intermediate→root) |
| FR-4 | Catat waktu, ukuran file, CPU, peak memory untuk tiap operasi × algoritma × trial |
| FR-5 | Sertifikat dapat dimuat browser nyata tanpa error trust (sudah tercapai) |
| FR-6 | Jalankan session resumption, ukur selisih overhead vs full handshake |
| FR-7 | Jalankan chain pruning (3 varian), ukur selisih byte terkirim |
| FR-8 | Seluruh hasil tersimpan sebagai CSV dengan skema konsisten |
| FR-9 | Model kapasitas: estimasi jumlah koneksi konkuren maksimum, tervalidasi load test nyata |
| FR-10 | Setiap modul punya dokumentasi/komentar penjelas mekanisme |

## 8. Skema Data (CSV)

`data/results.csv` — satu baris per pengukuran:

| Kolom | Tipe | Keterangan |
|---|---|---|
| run_id | string | UUID unik per sesi eksperimen |
| algorithm | string | mis. `ML-DSA-65`, `ECDSA-P384` |
| algorithm_family | string | `ML-DSA` / `ECC` |
| security_level | string | `2`,`3`,`5` (ML-DSA) atau perkiraan bit ECC |
| cert_level | string | `root` / `intermediate` / `leaf` |
| operation | string | `keygen`/`sign`/`verify`/`handshake_full`/`handshake_resumed` |
| trial_number | int | index trial (1..N) |
| time_ms | float | waktu wall-clock |
| cpu_time_ms | float | CPU time |
| peak_memory_kb | float | peak RSS |
| file_size_bytes | int | ukuran cert/kunci terkait |
| chain_length | int | jumlah cert dikirim |
| mitigation | string | `none`/`resumption`/`pruning`/`both` |
| handshake_bytes_total | int | total byte handshake |
| timestamp | string | ISO8601 |

Tabel kedua `data/capacity_profile.csv`:
`algorithm, mitigation, server_cores, est_max_concurrent, measured_max_concurrent, cpu_percent_at_saturation`

## 9. Tech Stack

- OpenSSL ≥ 3.5.x (sudah tersedia — native ML-DSA-44/65/87 & ECDSA P-256/384/521)
- Python 3.11+
- `cryptography`, `asn1crypto`, `psutil`, `scapy`, `pandas`, `matplotlib`, `pytest`
- `tshark` (CLI)
- Browser (sudah terbukti bisa baca sertifikat)

## 10. Fase Pengerjaan & Milestone

1. **M1 — Environment & PKI**: bootstrap.sh jalan bersih, 6 hierarki ter-generate dan lolos `openssl verify`.
2. **M2 — Inspeksi & Benchmark crypto**: x509_inspect.py membedah tiap cert, bench_crypto.py menghasilkan data keygen/sign/verify ≥100 trial/kombinasi.
3. **M3 — TLS handshake nyata**: server per algoritma berjalan, client bench mengukur handshake penuh, capture pcap tersimpan.
4. **M4 — Mitigasi**: resumption & pruning terukur, dibandingkan terhadap baseline M3.
5. **M5 — Profil kapasitas**: load test empiris + model, dibandingkan.
6. **M6 — Analisis & laporan**: seluruh CSV teragregasi, grafik, draf bab hasil skripsi.

Setiap milestone di atas akan dipecah lagi menjadi beberapa prompt manual (lihat Bagian 10) — jangan diminta sekaligus dalam satu sesi.

## 12. Kriteria Keberhasilan (Acceptance Criteria)

- Semua 6 hierarki lolos `openssl verify -CAfile root.crt -untrusted intermediate.crt leaf.crt`.
- Dataset CSV berisi minimal 100 trial per (algoritma × operasi), tanpa nilai kosong pada kolom wajib.
- Ada bukti kuantitatif overhead ML-DSA vs ECC (ukuran, waktu, CPU, memori) dengan interval kepercayaan.
- Ada bukti kuantitatif efek resumption dan efek pruning.
- Model kapasitas divalidasi dengan load test nyata.
- Setiap modul kode punya penjelasan tertulis mekanismenya.

## 13. Risiko & Pertanyaan Terbuka

- **Risiko**: parameter WSL2 (virtualized network stack) bisa mempengaruhi hasil timing handshake — mitigasi: jalankan di localhost, ulangi trial cukup banyak, laporkan sebagai batasan penelitian.
- **Risiko**: Cached Information Extension (RFC 7924) belum tentu didukung penuh library TLS yang dipakai — jika tidak tersedia, simulasikan pruning di level aplikasi dengan penjelasan eksplisit bahwa ini simulasi.
- **Pertanyaan terbuka**: spesifikasi server acuan untuk profil kapasitas — pakai resource WSL2 apa adanya, atau asumsi server produksi standar?
- **Pertanyaan terbuka**: apakah pembimbing mengharapkan uji jaringan nyata (bukan localhost) di tahap lanjut?

## 14. Referensi

- NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)
- RFC 8446 — TLS 1.3
- RFC 7924 — TLS Cached Information Extension
- RFC 8879 — TLS Certificate Compression
- OpenSSL 3.5/3.6 documentation — EVP_PKEY-ML-DSA, EVP_SIGNATURE-ML-DSA
