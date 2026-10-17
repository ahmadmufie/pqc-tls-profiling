#!/usr/bin/env bash
# diagnose_capacity_env.sh -- Cek cepat (~1-3 menit) untuk menjelaskan kenapa
# kapasitas 'none' ML-DSA-44 hasil M5 lama (jenuh di 1200) tidak cocok dengan
# hasil uji ulang barusan (masih 100% sukses sampai 6000). Jalankan ini di
# root project (setelah `source env.sh`), TIDAK perlu server jalan dulu.
#
# Tidak mengubah apa pun -- murni membaca konfigurasi sistem saat ini.

set -uo pipefail

echo "==================================================================="
echo "1. Batas file descriptor (ulimit -n)"
echo "==================================================================="
echo "Soft limit shell ini : $(ulimit -Sn)"
echo "Hard limit shell ini : $(ulimit -Hn)"
echo "(Makefile menjalankan 'ulimit -n 8192' sebelum tiap tes kapasitas --"
echo " pastikan itu benar2 ke-apply di proses python, bukan cuma shell induk)"
echo

echo "==================================================================="
echo "2. Range port ephemeral (dipakai client s_client tiap koneksi baru)"
echo "==================================================================="
if [ -r /proc/sys/net/ipv4/ip_local_port_range ]; then
  RANGE=$(cat /proc/sys/net/ipv4/ip_local_port_range)
  echo "ip_local_port_range : $RANGE"
  LOW=$(echo $RANGE | awk '{print $1}')
  HIGH=$(echo $RANGE | awk '{print $2}')
  echo "Total port tersedia  : $((HIGH-LOW))"
else
  echo "Tidak bisa baca ip_local_port_range (mungkin WSL membatasi akses /proc/sys)"
fi
echo

echo "==================================================================="
echo "3. TIME_WAIT reuse/recycle setting (pengaruh besar ke port habis)"
echo "==================================================================="
for f in tcp_tw_reuse tcp_fin_timeout tcp_max_tw_buckets; do
  path=/proc/sys/net/ipv4/$f
  if [ -r "$path" ]; then
    echo "$f : $(cat $path)"
  else
    echo "$f : (tidak terbaca)"
  fi
done
echo

echo "==================================================================="
echo "4. Jumlah koneksi TIME_WAIT / ESTABLISHED SAAT INI (baseline, idle)"
echo "==================================================================="
if command -v ss >/dev/null 2>&1; then
  echo "TOTAL socket TCP     : $(ss -tan | tail -n +2 | wc -l)"
  echo "TIME_WAIT saat ini   : $(ss -tan state time-wait | tail -n +2 | wc -l)"
  echo "ESTABLISHED saat ini : $(ss -tan state established | tail -n +2 | wc -l)"
else
  echo "'ss' tidak tersedia"
fi
echo

echo "==================================================================="
echo "5. CPU: jumlah core & load average saat ini"
echo "==================================================================="
nproc 2>/dev/null && echo "(jumlah core di atas)"
if [ -r /proc/loadavg ]; then
  echo "loadavg (1/5/15 menit): $(cat /proc/loadavg)"
fi
echo

echo "==================================================================="
echo "6. Uptime WSL (kalau baru reboot, sysctl bisa balik ke default beda"
echo "   dari saat data M5 lama direkam)"
echo "==================================================================="
uptime 2>/dev/null || cat /proc/uptime
echo

echo "==================================================================="
echo "KESIMPULAN YANG PERLU DICEK MANUAL:"
echo "- Kalau ip_local_port_range sempit (misal cuma ~28000 total) DAN"
echo "  tcp_tw_reuse=0, maka waktu run M5 lama kemungkinan 'jenuh' di 1200"
echo "  itu karena PORT HABIS (client kehabisan port lokal karena banyak"
echo "  TIME_WAIT), BUKAN karena kapasitas CPU server. Itu artinya batas"
echo "  1200 lama adalah artefak konfigurasi client, bukan kapasitas server"
echo "  sungguhan -- dan hasil baru (masih OK di 6000) yang lebih valid."
echo "- Kalau limit-limit di atas SAMA dengan saat M5 lama (Anda cek riwayat"
echo "  konfigurasi Anda), maka kemungkinan penyebabnya beban latar"
echo "  belakang WSL berbeda antar sesi -- perlu dicatat sebagai catatan"
echo "  threat-to-validity di skripsi (kapasitas absolut bergantung mesin)."
echo "==================================================================="
