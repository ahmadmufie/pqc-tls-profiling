#!/usr/bin/env bash
# Env eksplisit untuk OpenSSL 3.5.5 custom-build (mendukung ML-DSA native).
# Wajib di-source tiap sesi baru: source env.sh
export OSSL_HOME="/opt/openssl-3.5.5"
export PATH="${OSSL_HOME}/bin:${PATH}"
export LD_LIBRARY_PATH="${OSSL_HOME}/lib64:${LD_LIBRARY_PATH:-}"
