# =================================================================
# TAHAP 1: "BUILDER" - Dapur untuk memasak dependensi
# =================================================================
FROM python:3.10 AS builder

# Set direktori kerja
WORKDIR /app

# Install dependensi ke dalam sebuah virtual environment
# Ini menjaga semuanya tetap rapi di satu folder
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Salin file requirements dan install library
# Ini adalah bagian yang paling memakan ukuran
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# =================================================================
# TAHAP 2: "FINAL IMAGE" - Ruang saji yang bersih & efisien
# =================================================================
FROM python:3.10-slim

# Set direktori kerja
WORKDIR /app

# Salin VIRTUAL ENVIRONMENT yang sudah berisi library terinstall
# dari tahap "builder". Ini adalah langkah kuncinya! ✨
COPY --from=builder /opt/venv /opt/venv

# Salin KODE APLIKASI dan DATA Anda
COPY ./helper ./helper
COPY main.py .

# Atur PATH agar container menggunakan Python dari virtual environment
ENV PATH="/opt/venv/bin:$PATH"

# Definisikan command default saat container dijalankan
ENTRYPOINT ["python", "main.py"]