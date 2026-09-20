# Cybersecurity Vulnerability Audit Scanner & CLI Suite

> Platform audit kepatuhan keamanan web dan pengujian penetrasi (DevSecOps) berbasis **Web GUI** dan **Standalone CLI (Python / Node / Bun)** yang terinspirasi oleh standar **OWASP ZAP**, **ProjectDiscovery Nuclei**, dan **Burp Suite Pro**.

Dilengkapi dengan mesin agregasi temuan (*Finding Aggregation Engine*), kalkulasi skor CVSS v3.1 dinamis, filter Soft-404 anti false positive, dukungan upstream proxy (*Burp Suite / Tor*), ekspor laporan PDF eksekutif bilingual (Indonesia/Inggris), serta integrasi automasi CLI yang fleksibel.

---

## 📑 Daftar Isi

- [Fitur Utama](#-fitur-utama)
- [Persyaratan Sistem](#-persyaratan-sistem)
- [Setup & Instalasi Dependensi](#-setup--instalasi-dependensi)
  - [Opsi A: Python CLI (Paling Ringkas & Bebas Ribet)](#opsi-a-python-cli-paling-ringkas--bebas-ribet)
  - [Opsi B: 1-Click Setup Skrip (Otomatis Global)](#opsi-b-1-click-setup-skrip-otomatis-global)
  - [Opsi C: Bun (Instalasi Kilat untuk Web GUI)](#opsi-c-bun-instalasi-kilat-untuk-web-gui)
  - [Opsi D: NPM Tradisional](#opsi-d-npm-tradisional)
- [Panduan Penggunaan CLI (Usage Examples)](#-panduan-penggunaan-cli-usage-examples)
  - [Tabel Parameter Argumen CLI](#tabel-parameter-argumen-cli)
  - [Contoh Perintah Eksekusi Praktis](#contoh-perintah-eksekusi-praktis)
- [Panduan Penggunaan Antarmuka Web (Web GUI)](#-panduan-penggunaan-antarmuka-web-web-gui)
- [Konfigurasi Upstream Proxy (Burp Suite, ZAP, Tor)](#-konfigurasi-upstream-proxy-burp-suite-zap-tor)
- [Struktur Berkas Proyek](#-struktur-berkas-proyek)
- [Penafian Etika Keamanan (Disclaimer)](#-penafian-etika-keamanan-disclaimer)
- [Lisensi](#-lisensi)

---

## 🚀 Fitur Utama

### 1. Mesin Audit Cerdas & Aggregation Engine
- **Agregasi Otomatis (Deduplikasi)**: Masalah *missing security headers* (CSP, X-Frame-Options, HSTS, X-Content-Type-Options) dikonsolidasikan menjadi 1 Temuan Induk (*Aggregated Parent Finding*) dengan sub-checks terstruktur agar laporan rapi dan tidak *inflated*.
- **Kontekstual Scoring (CVSS v3.1)**: Skor keparahan disesuaikan secara dinamis jika terdeteksi parameter yang berisiko refleksi XSS atau ketiadaan proteksi Clickjacking.
- **Filter Soft-404 & Multi-Condition Matcher**: Menghilangkan *false positive* pada endpoint yang mengembalikan kode status HTTP 200 tetapi sebenarnya adalah halaman galat/kustom HTML.

### 2. Berbagai Pilihan Eksekusi
- **Standalone Python CLI (`cyber_audit.py`)**: Berjalan mandiri hanya dengan Python 3 dan pustaka `requests`/`rich` dari `requirements.txt`.
- **Modern Web Dashboard**: Antarmuka responsif dengan terminal log langsung, filter tingkat keparahan, visual customizer, dan ekspor PDF.
- **Batch Recon Integrator**: Mendukung input daftar subdomain hasil *Subfinder*, *Assetfinder*, atau *Amass*.

### 3. Ekspor Laporan PDF Kepatuhan & Bilingual
- Menghasilkan berkas PDF audit resmi dengan grafik distribusi keparahan, proof-of-concept evidence, serta panduan konfigurasi server (Nginx, Apache, Express, LiteSpeed, Cloudflare) dalam pilihan bahasa **Inggris (EN)** atau **Indonesia (ID)**.

---

## 📦 Persyaratan Sistem

Pilih salah satu lingkungan yang paling nyaman untuk Anda:

| Lingkungan | Versi Minimal | Kebutuhan |
| :--- | :--- | :--- |
| **Python** (Direkomendasikan untuk CLI) | Python `>= 3.8` | `pip install -r requirements.txt` |
| **Bun** (Alternatif Tercepat untuk Web) | Bun `>= 1.0` | `bun install` |
| **Node.js / NPM** | Node `>= 18.0` | `npm install --legacy-peer-deps` |
| **Sistem Operasi** | Linux, macOS, WSL2, Windows | Terminal Bash / PowerShell |

---

## 🛠 Setup & Instalasi Dependensi

Jika Anda merasa `npm` sering mengalami konflik versi atau memakan waktu lama, gunakan opsi **Python** atau **Bun** di bawah ini:

### Opsi A: Python CLI (Paling Ringkas & Bebas Ribet)
Jika Anda hanya ingin melakukan scanning langsung dari terminal tanpa menjalankan server web:

1. Pastikan Python 3 dan pip sudah terpasang:
   ```bash
   python3 --version
   ```

2. Pasang dependensi dari berkas `requirements.txt` atau via `pyproject.toml`:
   ```bash
   # Menggunakan requirements.txt
   pip install -r requirements.txt

   # Atau pasang sebagai paket lokal yang dapat dieksekusi secara global
   pip install .
   ```

3. Jalankan pemindaian langsung:
   ```bash
   python3 cyber_audit.py -u https://example.com
   ```

---

### Opsi B: 1-Click Setup Skrip (Otomatis Global)
Skrip `setup.sh` akan mendeteksi lingkungan Anda secara otomatis (Python/Bun/NPM), memasang dependensi, dan mendaftarkan perintah global `cyber-audit` serta `cyber-audit-web` ke sistem PATH.

```bash
chmod +x setup.sh && ./setup.sh
```

Setelah dijalankan, Anda dapat langsung mengetikkan perintah ini dari folder mana saja (termasuk Home `~`):
```bash
# Menjalankan Web GUI
cyber-audit-web

# Menjalankan audit CLI
cyber-audit -u https://example.com -p high
```

---

### Opsi C: Bun (Instalasi Kilat untuk Web GUI)
Jika Anda ingin menjalankan Web GUI tanpa beban NPM:

```bash
# Pasang dependensi dalam hitungan detik
bun install

# Jalankan Web GUI
bun run dev
```
Akses di peramban: `http://localhost:3000`

---

### Opsi D: NPM Tradisional
Jika Anda tetap ingin menggunakan NPM:

```bash
# Gunakan flag legacy-peer-deps untuk mencegah konflik peer dependency
npm install --legacy-peer-deps

# Jalankan Web GUI
npm run dev
```

---

## 💻 Panduan Penggunaan CLI (Usage Examples)

Eksekusi pemindai dapat dilakukan via skrip Python `python3 cyber_audit.py` atau perintah global `cyber-audit`.

### Tabel Parameter Argumen CLI

| Parameter Pendek | Parameter Panjang | Nilai / Format | Penjelasan & Fungsi |
| :--- | :--- | :--- | :--- |
| `-u` | `--url` | `<URL>` | Menentukan URL target tunggal yang akan diaudit (contoh: `https://smkn3kotabekasi.sch.id`). |
| `-l` | `--list` | `<FILE_PATH>` | Membaca daftar target subdomain/URL dari berkas teks (satu target per baris). |
| `-p` | `--severity` | `critical`, `high`, `medium`, `low`, `info`, `all` | Menyaring temuan berdasarkan batas ambang keparahan minimal (Default: `all`). |
| `-x` | `--proxy` | `<PROXY_URL>` | Merutekan seluruh request HTTP/HTTPS melalui upstream proxy (contoh: `http://127.0.0.1:8080` untuk Burp Suite Pro atau `socks5://127.0.0.1:9050` untuk Tor). |
| `-t` | `--timeout` | `<SECONDS>` | Batas waktu tunggu respons HTTP dalam satuan detik (Default: `8`). |
| `-o` | `--output` | `<FILE_PATH>` | Menyimpan hasil audit terstruktur ke dalam berkas JSON (contoh: `hasil_audit.json`). |
| `--silent` | `--silent` | *Flag* | Mode senyap: menyembunyikan banner ASCII saat scanner dijalankan. |
| `-h` | `--help` | *Flag* | Menampilkan ringkasan bantuan dan dokumentasi opsi parameter. |

---

### Contoh Perintah Eksekusi Praktis

#### 1. Audit Target Tunggal Sederhana
```bash
python3 cyber_audit.py -u https://smkn3kotabekasi.sch.id
```

#### 2. Audit Hanya Temuan High & Critical Melalui Proxy Burp Suite Pro
```bash
python3 cyber_audit.py -u https://target.com -p high -x http://127.0.0.1:8080
```

#### 3. Mengintegrasikan (*Piping*) Output Subfinder ke Scanner
```bash
subfinder -d target.sch.id -silent | tee subdomains.txt
python3 cyber_audit.py -l subdomains.txt -p medium -o hasil_recon.json
```

#### 4. Audit Daftar Target Melalui Jaringan Anonim Tor (SOCKS5)
```bash
python3 cyber_audit.py -l targets.txt -x socks5://127.0.0.1:9050 --timeout 15 -o tor_audit.json
```

#### 5. Otomatisasi Scheduled Cron Job di Linux Server
```bash
# Menjalankan audit harian setiap pukul 02:00 pagi dan menyimpan log
(crontab -l 2>/dev/null; echo "0 2 * * * /usr/bin/python3 /opt/cyber-audit/cyber_audit.py -u https://target.com -p high -o /var/log/audit.json >> /var/log/audit.log 2>&1") | crontab -
```

---

## 🖥 Panduan Penggunaan Antarmuka Web (Web GUI)

1. **Audit Panel**:
   - Masukkan URL target pada kolom pencarian.
   - Aktifkan template audit yang diinginkan (OWASP Security Headers, Sensitive .env Leak, Git Exposure, Spring Boot Actuator, dll).
   - Klik **Mulai Audit Keamanan** untuk melihat visual log di terminal auditor.

2. **Ekspor Laporan PDF**:
   - Pada tab **Temuan Audit**, pilih bahasa laporan (**EN** untuk English atau **ID** untuk Bahasa Indonesia).
   - Klik **Export Audit PDF** untuk mengunduh laporan berformat dokumen resmi.

3. **Panduan Pengerasan Server (Server Hardening)**:
   - Pilih tab server Anda (Nginx, Apache, Express, LiteSpeed, Cloudflare) untuk menyalin snippet konfigurasi *security headers* siap pakai.

---

## 🔌 Konfigurasi Upstream Proxy (Burp Suite, ZAP, Tor)

| Perangkat Lunak | URL Proxy Standar | Catatan Konfigurasi |
| :--- | :--- | :--- |
| **Burp Suite Pro** | `http://127.0.0.1:8080` | Aktifkan listener pada tab *Proxy > Options*. Nonaktifkan TLS certificate validation jika menggunakan sertifikat default. |
| **OWASP ZAP** | `http://127.0.0.1:8081` | Pastikan ZAP berjalan di port 8081. |
| **Tor Network** | `socks5://127.0.0.1:9050` | Jalankan daemon Tor (`sudo systemctl start tor`). |
| **Corporate Proxy** | `http://proxy.corp.net:3128` | Mendukung basic authentication dan custom headers. |

---

## 📁 Struktur Berkas Proyek

```text
├── cyber_audit.py            # Standalone Python CLI Auditor
├── requirements.txt          # Spesifikasi dependensi Python (requests, urllib3, rich, dll)
├── pyproject.toml            # Metadata build & packaging Python modern
├── setup.sh                  # One-Click Setup & Global CLI Installer (Bash)
├── LICENSE                   # Lisensi Open-Source (MIT License)
├── README.md                 # Dokumentasi panduan lengkap
├── server.ts                 # Backend Server & API Gateway (Express + Vite)
├── server/
│   ├── scanner.ts            # Vulnerability Engine & Aggregation Pipeline
│   ├── cve-database.ts       # Definisi Database CVE & Rule Matchers
│   └── cli-script.ts         # Node/TypeScript CLI runner
└── src/
    ├── App.tsx               # Main Application Layout
    ├── components/           # Sub-komponen (FindingsList, ScannerPanel, dll)
    └── utils/
        ├── pdfGenerator.ts   # Dynamic Localized PDF Layout Engine
        └── reportLocales.ts  # Kamus Lokalisasi Laporan (ID & EN)
```

---

## ⚖️ Penafian Etika Keamanan (Disclaimer)

> **PERINGATAN PENTING**: 
> Perangkat lunak ini dibuat dan didistribusikan semata-mata untuk tujuan **pengujian keamanan yang sah (*authorized penetration testing*)**, audit kepatuhan internal (*security compliance*), penelitian kerentanan defensif (*defensive hardening*), dan kegiatan *bug bounty* resmi.
> 
> Dilarang keras menggunakan perangkat lunak ini untuk memindai, menyerang, atau mengeksploitasi sistem, server, atau jaringan milik pihak ketiga tanpa izin tertulis yang sah dari pemilik sistem. Penulis, pengembang, dan kontributor **tidak bertanggung jawab** atas segala bentuk penyalahgunaan, kerugian, pelanggaran hukum, atau kerusakan yang ditimbulkan oleh penggunaan alat ini.

---

## 📄 Lisensi

Proyek ini dilisensikan di bawah lisensi terbuka **MIT License**. Lihat berkas [LICENSE](./LICENSE) untuk rincian lengkap.
