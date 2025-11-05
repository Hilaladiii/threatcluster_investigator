#!/bin/sh

echo "Memulai analisis log..."
python3 main.py "$@"

echo "Analisis selesai. Laporan dihasilkan di /app/output."

if [ ! -f /app/output/index.html ]; then
    echo "Error: index.html tidak ditemukan di /app/output."
    exit 1
fi

echo "Menjalankan server web di port 8000..."
python3 -m http.server 8000 --directory /app/output