# Dokumentasi Teknis & Pemetaan Requirement

## Pemetaan Milestone -> Functional Requirement -> Perintah -> Output

| Milestone | FR    | Perintah `make`         | Output                                  |
|-----------|-------|--------------------------|------------------------------------------|
| M1        | FR-1  | `make sertifikat`        | `pki/<algo>/*`                           |
| M1        | FR-2  | `make validasi-rantai`   | stdout (valid/tidak per rantai)          |
| M2        | FR-3  | `make ukuran-sertifikat` | `data/raw/x509_component_sizes.csv`      |
| M2        | FR-4  | `make benchmark-crypto`  | `data/raw/bench_crypto.csv`              |
| M3        | FR-5  | `make handshake`         | `data/raw/tls_handshake_bench.csv`       |
| M3        | FR-6  | `make handshake`         | (kolom mitigation=resumption di file yang sama) |
| M4        | FR-7  | `make mitigasi`          | `data/raw/chain_pruning_bench.csv`       |
| M4        | FR-8  | `make gabung`            | `data/results.csv` (8418 baris)          |
| M5        | FR-9  | `make kapasitas-penuh`   | `data/capacity_profile.csv` (12 baris)   |
| M6        | -     | (manual, bab analisis)   | draf laporan                              |
| -         | FR-10 | (manual, review)         | dokumentasi modul (file ini)             |

## Ringkasan temuan kunci (per `make ringkasan`)

- **Ukuran sertifikat**: ECC 553-688 bytes; ML-DSA 4.147-7.634 bytes (7-11x lebih besar).
- **Waktu keygen/sign/verify**: relatif setara antar semua algoritma (~9-12ms) --
  overhead PQC di FR-4 **bukan** di komputasi, tapi di ukuran data (lihat FR-5/6).
- **Reduksi byte on-wire lewat resumption**: ECC ~26-30%, ML-DSA **74-84%** --
  resumption jauh lebih berdampak untuk PQC karena menghapus pengiriman
  sertifikat besar berulang kali.
- **Chain pruning**: mengurangi ukuran handshake full secara konsisten di semua
  algoritma (leaf-only vs full: ECC turun ~18-21%, ML-DSA turun ~43-48%).
- **Kapasitas server (FR-9)**: bottleneck utama adalah **antrean/latensi**, bukan
  CPU murni -- CPU saturasi teoretis (`est_max_concurrent`) berkisar 480-760,
  jauh di bawah beberapa `measured_max_concurrent` (2500-5000), karena
  `s_server` tanpa `-multi` bersifat serial per koneksi.

## Anomali yang perlu dijelaskan saat sidang (sudah tereproduksi 2x, bukan artefak)

1. **ECDSA-P384 dan ECDSA-P521 (tanpa mitigasi) jenuh lebih cepat dan punya
   latensi baseline lebih tinggi daripada semua varian ML-DSA**, walau ukuran
   sertifikatnya jauh lebih kecil. Diuji ulang dengan pembersihan TIME_WAIT
   socket penuh sebelum tiap kombinasi -- anomali tetap muncul. Hipotesis
   kerja: build OpenSSL 3.5.5 di lingkungan ini tidak punya optimasi
   assembly untuk kurva P-384/P-521 sebaik P-256, sehingga operasi
   ECDH/ECDSA di kurva itu lebih mahal secara komputasi meski secara teori
   ukuran data lebih kecil. Cross-check: waktu sign/verify mentah P-384/P-521
   di `data/results.csv` (operation=sign/verify) untuk memastikan kurva ini
   memang lebih lambat secara komputasi murni.
2. **ML-DSA-65 dengan resumption menunjukkan kapasitas terukur lebih rendah
   (200) daripada versi tanpa mitigasi (600)** -- ini kemungkinan besar
   keterbatasan metodologi kriteria saturasi relatif (latensi >= 3x baseline):
   baseline latensinya sangat rendah (47.7ms) sehingga ambang jenuhnya sangat
   sempit, dan lonjakan kecil akibat variasi sistem sudah cukup memicu deteksi
   "jenuh". Perlu disebutkan sebagai keterbatasan (threat to validity) di bab
   metodologi/analisis, bukan disembunyikan.

## Verifikasi Antarmuka CLI Tiap Skrip (FR-10)

Dikonfirmasi langsung lewat `--help` pada 2026-08-09 supaya `Makefile` tidak berasumsi
salah soal argumen yang diterima tiap skrip:

| Skrip                    | Argumen CLI terkonfirmasi                                   | Catatan |
|---------------------------|--------------------------------------------------------------|---------|
| `gen_pki.py`               | **Tidak ada.** Argumen (termasuk `--help`) diabaikan sepenuhnya. | Selalu membangun ke-6 hierarki sekaligus dalam satu run; tidak bisa memilih satu algoritma tanpa mengubah kode skrip. |
| `bench_crypto.py`          | `--trials`, `--out`                                           | Tidak ada `--algos` -- selalu membenchmark ke-6 algoritma sekaligus. |
| `tls_client_bench.py`      | `--trials`, `--algos {...}`, `--out`                          | Sesuai asumsi Makefile. |
| `mitigation_pruning.py`    | `--trials`, `--algos {...}`, `--modes {full,no-root,leaf-only}`, `--out` | Sesuai asumsi Makefile. |
| `capacity_model.py`        | `--algos {...}`, `--mitigations {none,resumption}`, `--levels`, `--out` | Sesuai asumsi Makefile. |

`Makefile` sudah diperbarui agar tidak lagi menawarkan `HANYA=<algo>` pada target
`sertifikat` dan `benchmark-crypto`, karena kedua skrip itu tidak mendukungnya.

## Troubleshooting

- **Muncul prompt `[sudo] password for ...` di akhir run**: `tls_client_bench.py`
  punya `atexit` handler pembersihan tshark yang selalu memanggil `sudo`.
  Jalankan `sudo -v` sebelum memulai run panjang; harmless, tidak memengaruhi
  data yang sudah ditulis ke CSV.
- **CPU% tidak pernah mencapai 90% walau server terlihat penuh**: `s_server`
  tanpa `-multi` serial secara desain -- gunakan kriteria latensi
  (`capacity_model.py` versi terkini), bukan CPU%, sebagai indikator jenuh.
- **Port 8443-8448 "address already in use"**: jalankan `make bersihkan` untuk
  mematikan proses `openssl s_server` yang mungkin masih nyangkut dari run
  sebelumnya yang terhenti paksa (Ctrl+C di tengah).
- **`ss -tanH state time-wait` menunjukkan ribuan socket**: normal setelah
  test load tinggi; `capacity_model.py` versi terkini sudah menunggu socket
  ini reda otomatis sebelum kombinasi berikutnya (lihat `wait_for_clean_sockets`).

## Skema data

Lihat PRD Bagian 8 untuk skema kolom lengkap `data/results.csv` dan
`data/capacity_profile.csv`. Kolom kunci:
- `data/results.csv`: `algorithm, algorithm_family, operation, mitigation,
  chain_length, time_ms, handshake_bytes_total, file_size_bytes, ...`
- `data/capacity_profile.csv`: `algorithm, mitigation, est_max_concurrent,
  measured_max_concurrent, cpu_percent_at_saturation`
