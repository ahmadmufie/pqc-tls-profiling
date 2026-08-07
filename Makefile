SHELL := /bin/bash
.ONESHELL:
.DEFAULT_GOAL := help

ALGOS  := mldsa44 mldsa65 mldsa87 ecc-p256 ecc-p384 ecc-p521
TRIAL  ?= 100
CTRIAL ?= 3
ALGO   ?= mldsa44

# Flag gaya "PAKSA=1 make sertifikat" -- ifdef mengecek apakah variabel diisi apa saja
VBOSE  := $(if $(RINCI),-x,)

.PHONY: help persiapan \
        sertifikat _sertifikat-satu validasi-rantai ukuran-sertifikat \
        benchmark-crypto \
        server-mulai server-status server-stop handshake \
        mitigasi \
        gabung \
        kapasitas kapasitas-penuh \
        demo ringkasan \
        bersihkan

help:
	@echo ""
	@echo "PERSIAPAN LINGKUNGAN"
	@echo "  make persiapan                 cek openssl, oqs-provider, port kosong, struktur folder"
	@echo ""
	@echo "MEMBUAT & MEMERIKSA SERTIFIKAT"
	@echo "  make sertifikat                bangun 6 hierarki PKI yang belum ada"
	@echo "  make sertifikat PAKSA=1        bangun ulang SEMUA hierarki dari nol"
	@echo "  make sertifikat HANYA=mldsa44  bangun salah satu hierarki"
	@echo "  make sertifikat RINCI=1        tampilkan tiap perintah yang dijalankan"
	@echo "  make validasi-rantai           validasi rantai sertifikat"
	@echo "  make ukuran-sertifikat         ukur ukuran tiap komponen sertifikat"
	@echo ""
	@echo "BENCHMARK KRIPTOGRAFI"
	@echo "  make benchmark-crypto              keygen/sign/verify, $(TRIAL) trial (data resmi)"
	@echo "  make benchmark-crypto CEPAT=1       versi cepat ($(CTRIAL) trial) untuk demo, ke /tmp"
	@echo "  make benchmark-crypto HANYA=mldsa44 satu algoritma saja"
	@echo ""
	@echo "SERVER & HANDSHAKE TLS"
	@echo "  make server-mulai ALGO=mldsa44  nyalakan server TLS di background (demo manual s_client)"
	@echo "  make server-status ALGO=mldsa44 lihat apakah server itu masih aktif"
	@echo "  make server-stop ALGO=mldsa44   hentikan server itu"
	@echo "  make handshake                  benchmark handshake full vs resumption, $(TRIAL) trial"
	@echo "  make handshake CEPAT=1          versi cepat ($(CTRIAL) trial), ke /tmp"
	@echo ""
	@echo "MITIGASI CHAIN PRUNING"
	@echo "  make mitigasi                   benchmark potong rantai sertifikat, $(TRIAL) trial"
	@echo "  make mitigasi CEPAT=1           versi cepat ($(CTRIAL) trial), ke /tmp"
	@echo ""
	@echo "KONSOLIDASI DATA"
	@echo "  make gabung                     gabungkan semua data mentah ke data/results.csv"
	@echo ""
	@echo "KAPASITAS SERVER / LOAD TEST"
	@echo "  make kapasitas ALGO=mldsa44     uji kapasitas 1 algoritma, skala mini, ke /tmp"
	@echo "  make kapasitas-penuh            uji kapasitas 12 kombinasi penuh (~18 menit, data resmi)"
	@echo ""
	@echo "DEMO & RINGKASAN"
	@echo "  make demo                       jalankan seluruh pipeline versi mini end-to-end (~2-3 menit)"
	@echo "  make ringkasan                  cetak ringkasan hasil dari data RESMI (instan, tanpa run ulang)"
	@echo ""
	@echo "UTILITAS"
	@echo "  make bersihkan                  matikan server openssl yang nyangkut, hapus file demo /tmp"
	@echo ""
	@echo "Catatan: semua target dengan CEPAT=1 menulis ke /tmp, TIDAK PERNAH menimpa data resmi di data/."
	@echo ""

# ---------- PERSIAPAN ----------

persiapan:
	source env.sh
	echo "-- Cek openssl --"
	openssl version || { echo "openssl custom tidak ditemukan. Jalankan: source env.sh"; exit 1; }
	echo "-- Cek provider oqs --"
	openssl list -providers | grep -qi oqs && echo "  oqs-provider: OK" || echo "  PERINGATAN: oqs-provider tidak terdeteksi"
	echo "-- Cek port 8443-8448 kosong --"
	for p in 8443 8444 8445 8446 8447 8448; do \
		if ss -tanH "( sport = :$$p )" | grep -q .; then echo "  PERINGATAN: port $$p sedang dipakai"; \
		else echo "  port $$p: bebas"; fi; \
	done
	echo "-- Cek hierarki PKI --"
	for a in $(ALGOS); do \
		if [ -f pki/$$a/leaf.crt ]; then echo "  pki/$$a: ADA"; else echo "  pki/$$a: BELUM ADA"; fi; \
	done

# ---------- SERTIFIKAT (FR-1, FR-2, FR-3) ----------

sertifikat:
ifdef HANYA
	$(MAKE) _sertifikat-satu ALGO=$(HANYA)
else
	for a in $(ALGOS); do $(MAKE) _sertifikat-satu ALGO=$$a; done
endif

# ASUMSI: gen_pki.py menerima --algo <nama> dan --verbose. Perlu diverifikasi.
_sertifikat-satu:
	source env.sh
ifdef PAKSA
	echo "  [ulang]  pki/$(ALGO) (PAKSA=1)"
	rm -rf pki/$(ALGO)
	bash $(VBOSE) -c "python3 src/gen_pki.py --algo $(ALGO) $(if $(RINCI),--verbose,)"
else
	if [ -f pki/$(ALGO)/leaf.crt ]; then \
		echo "  [lewati] pki/$(ALGO) sudah ada (pakai PAKSA=1 untuk membangun ulang)"; \
	else \
		echo "  [bangun] pki/$(ALGO)"; \
		bash $(VBOSE) -c "python3 src/gen_pki.py --algo $(ALGO) $(if $(RINCI),--verbose,)"; \
	fi
endif

validasi-rantai:
	source env.sh && bash src/chain_validation.sh

ukuran-sertifikat:
	source env.sh && python3 src/x509_inspect.py

# ---------- BENCHMARK KRIPTOGRAFI (FR-4) ----------
# ASUMSI: bench_crypto.py menerima --trials, --algos, --out.

benchmark-crypto:
ifdef CEPAT
	source env.sh && python3 src/bench_crypto.py --trials $(CTRIAL) $(if $(HANYA),--algos $(HANYA),) --out /tmp/demo_bench.csv
else
	source env.sh && python3 src/bench_crypto.py --trials $(TRIAL) $(if $(HANYA),--algos $(HANYA),)
endif

# ---------- SERVER & HANDSHAKE (FR-5, FR-6) ----------

server-mulai:
	source env.sh
	nohup python3 src/tls_server.py --algo $(ALGO) > /tmp/tls_server_$(ALGO).log 2>&1 &
	echo $$! > /tmp/tls_server_$(ALGO).pid
	sleep 1
	echo "Server $(ALGO) berjalan di background (PID $$(cat /tmp/tls_server_$(ALGO).pid))."
	echo "Log: /tmp/tls_server_$(ALGO).log -- lihat baris 'Uji manual' untuk perintah openssl s_client."

server-status:
	if [ -f /tmp/tls_server_$(ALGO).pid ] && kill -0 $$(cat /tmp/tls_server_$(ALGO).pid) 2>/dev/null; then \
		echo "Server $(ALGO): AKTIF (PID $$(cat /tmp/tls_server_$(ALGO).pid))"; \
	else \
		echo "Server $(ALGO): TIDAK aktif."; \
	fi

server-stop:
	if [ -f /tmp/tls_server_$(ALGO).pid ]; then \
		kill $$(cat /tmp/tls_server_$(ALGO).pid) 2>/dev/null; \
		rm -f /tmp/tls_server_$(ALGO).pid; \
		echo "Server $(ALGO) dihentikan."; \
	else \
		echo "Tidak ada server $(ALGO) yang tercatat aktif."; \
	fi

handshake:
ifdef CEPAT
	source env.sh && sudo -v && python3 src/tls_client_bench.py --trials $(CTRIAL) --out /tmp/demo_handshake.csv
else
	source env.sh && sudo -v && python3 src/tls_client_bench.py --trials $(TRIAL)
endif

# ---------- MITIGASI (FR-7) ----------

mitigasi:
ifdef CEPAT
	source env.sh && python3 src/mitigation_pruning.py --trials $(CTRIAL) --out /tmp/demo_pruning.csv
else
	source env.sh && python3 src/mitigation_pruning.py --trials $(TRIAL)
endif

# ---------- KONSOLIDASI (FR-8) ----------

gabung:
	source env.sh && python3 src/consolidate_results.py

# ---------- KAPASITAS (FR-9) ----------

kapasitas:
	source env.sh && ulimit -n 8192 && sudo -v
	python3 src/capacity_model.py --algos $(ALGO) --mitigations none resumption \
	  --levels 50 100 200 --out /tmp/capacity_quick.csv
	cat /tmp/capacity_quick.csv

kapasitas-penuh:
	source env.sh && ulimit -n 8192 && sudo -v
	python3 src/capacity_model.py --levels 200 600 1200 1800 2500 3500 5000 \
	  --out data/capacity_profile.csv

# ---------- DEMO & RINGKASAN ----------

demo:
	source env.sh
	echo ">>> [1/4] Benchmark kripto mini (FR-4)"
	python3 src/bench_crypto.py --trials 3 --out /tmp/demo_bench.csv
	echo ">>> [2/4] Handshake TLS nyata mini (FR-5/FR-6)"
	sudo -v && python3 src/tls_client_bench.py --algos mldsa44 --trials 3 --out /tmp/demo_handshake.csv
	echo ">>> [3/4] Chain pruning mini (FR-7)"
	python3 src/mitigation_pruning.py --algos mldsa44 --trials 3 --out /tmp/demo_pruning.csv
	echo ">>> [4/4] Kapasitas mini (FR-9)"
	ulimit -n 8192 && python3 src/capacity_model.py --algos mldsa44 --mitigations none resumption \
	  --levels 50 100 200 --out /tmp/demo_capacity.csv
	echo ">>> SELESAI. Seluruh pipeline berhasil berjalan end-to-end (skala mini)."

ringkasan:
	source env.sh && python3 src/report_summary.py

# ---------- UTILITAS ----------

bersihkan:
	-sudo pkill -9 -f "openssl s_server" 2>/dev/null; true
	rm -f /tmp/tls_server_*.pid /tmp/tls_server_*.log /tmp/demo_*.csv /tmp/capacity_quick.csv
	echo "Selesai membersihkan proses server & file demo sementara."
