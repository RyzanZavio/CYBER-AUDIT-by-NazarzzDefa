# Cybersecurity Vulnerability Audit Scanner

> Platform audit keamanan dan simulasi penetrasi (DevSecOps) berbasis web dan terminal CLI yang terinspirasi oleh **OWASP ZAP**, **ProjectDiscovery Nuclei**, dan **Burp Suite Pro**. Dilengkapi dengan otomatisasi template YAML, pemindaian massal daftar subdomain (*Subfinder*), sistem ekstensi modular, rute *upstream proxy*, webhooks Discord/Slack, laporan PDF eksekutif, serta penyesuaian visual (*visual customizer*).

---

## 📑 Daftar Isi

- [Fitur Utama](#-fitur-utama)
- [Arsitektur &amp; Teknologi](#-arsitektur--teknologi)
- [Persyaratan Sistem](#-persyaratan-sistem)
- [Panduan Instalasi &amp; Menjalankan Aplikasi](#-panduan-instalasi--menjalankan-aplikasi)
- [Panduan Penggunaan Antarmuka Web](#-panduan-penggunaan-antarmuka-web)
- [Panduan Integrasi Linux &amp; WSL CLI](#-panduan-integrasi-linux--wsl-cli)
- [Konfigurasi Upstream Proxy (Burp Suite, ZAP, Tor)](#-konfigurasi-upstream-proxy-burp-suite-zap-tor)
- [Sistem Ekstensi Keamanan (Extension Store)](#-sistem-ekstensi-keamanan-extension-store)
- [Penyesuaian Visual &amp; Audio (Visual Customizer)](#-penyesuaian-visual--audio-visual-customizer)
- [Dokumentasi REST API](#-dokumentasi-rest-api)
- [Disclaimer Etika Keamanan](#-disclaimer-etika-keamanan)

---

## 🚀 Fitur Utama

### 1. Mesin Pemindai Kerentanan (Core Vulnerability Engine)
- **Aturan Berbasis YAML Fleksibel**: Kompatibel dengan sintaksis deklaratif mirip *Nuclei* (HTTP methods, headers, payload fuzzing, status code matchers, dan regex word matchers).
- **Katalog Standar Industri**: Deteksi otomatis kerentanan OWASP Top 10, kebocoran kredensial `.env` / Git config, CORS misconfiguration, missing security headers (HSTS/CSP), open redirect, serta TLS weak cipher detection.
- **Kalkulasi CVSS 3.1 & CWE**: Setiap temuan dilengkapi skor CVSS kuantitatif, kategori OWASP 2021, identifikasi kelemahan CWE, serta panduan mitigasi (*remediation step*).

### 2. Batch Scanning &amp; Subfinder Drag-and-Drop
- **Dukungan File Fleksibel**: Drag-and-drop file `.txt`, `.csv`, `.json`, atau log output langsung dari laptop/flashdisk (misal output dari `subfinder`, `assetfinder`, atau `amass`).
- **Pembersih Target Otomatis**: Menghapus protokol `http://` / `https://`, URL paths, port, karakter wildcard `*.`, dan membersihkan duplikasi secara otomatis.
- **Eksekusi Paralel & Progres Visual**: Menampilkan metrik penyelesaian, filter tingkat keparahan (*severity breakdown*), serta tombol ekspor PDF gabungan.

### 3. Konfigurasi Upstream Proxy & Anonymization
- **1-Click Presets**:
  - **Burp Suite Pro** (`http://127.0.0.1:8080`) dengan bypass verifikasi sertifikat self-signed CA.
  - **OWASP ZAP** (`http://127.0.0.1:8081`) untuk proxying audit pasif/aktif lokal.
  - **Tor SOCKS5 Anonymizer** (`socks5://127.0.0.1:9050`) untuk merutekan traffic melalui jaringan privasi Tor.
  - **Corporate Proxy**: Dukungan autentikasi kredensial (Basic Auth username & password) dan custom spoofed User-Agent.
- **Live Proxy Tunnel Test**: Tombol uji koneksi real-time untuk memvalidasi latensi (ms) dan memeriksa IP keluar publik (*egress outgoing IP*).

### 4. Ekstensi Keamanan Modular (Extension Store)
- **Extension Packs Bawaan**:
  - *OWASP API Security Top 10 Pack* (BOLA, Broken Object Level Auth, Mass Assignment).
  - *Burp Suite Active Fuzzing Pack* (SQLi probe, Reflected XSS, Path Traversal).
  - *Subdomain Takeover & Dangling DNS Pack* (S3, GitHub Pages, Heroku, Azure pointers).
  - *JWT & Token Misconfiguration Pack* (`none` algorithm, weak HMAC secrets).
- **Import Ekstensi Mandiri**: Pengguna dapat mengunggah manifest ekstensi baru berformat `.json` atau berkas `.yaml` langsung dari komputer atau flashdisk.

### 5. Penyesuaian Visual &amp; Tema (Visual Customizer)
- **7 Pilihan Tema Warna**:
  - `Cyber Slate`: Nuansa default DevSecOps biru tua & cyan.
  - `Matrix Phosphor`: Tema hacker layar hijau CRT retro pekat.
  - `OLED Pure Black`: Kontras mutlak `#000000` ramah layar OLED.
  - `Red Team Ops`: Nuansa simulasi musuh (adversary) dengan aksen crimson.
  - `Synthwave Neon`: Estetika cyberpunk violet & fuchsia.
  - `Amber 2800K`: Terminal vintage monitor tabung bernuansa hangat.
  - `White Hat Lab`: Mode terang (clean light) berdaya kontras tinggi untuk kebutuhan laporan kepatuhan.
- **Tipografi & Skala Teks**: Pilihan Monospace, Clean Sans, atau Vintage Retro VT320 dengan penskalaan teks (90% - 120%).
- **Kerapatan Layar (UI Density)**: Mode Kompak, Standar, dan Lega.
- **Efek Retro & Audio Web API**: Efek scanlines CRT tabung, dot matrix grid, dan umpan balik suara klik serta nada alarm deteksi kerentanan.

### 6. Otomatisasi & Pelaporan
- **Laporan PDF Eksekutif**: Ringkasan kepatuhan C-Level, grafik distribusi keparahan, detail bukti temuan (*proof-of-concept evidence*), dan referensi keamanan.
- **Notifikasi Webhook Discord & Slack**: Pengiriman payload instan saat temuan dengan tingkat keparahan tertentu terdeteksi.
- **Penjadwal Harian (Daily Cron)**: Otomatisasi audit harian pada jam tertentu (UTC).

---

## 🛠 Arsitektur & Teknologi

- **Frontend**: React 18, TypeScript, Tailwind CSS, Lucide React, jsPDF, Framer Motion.
- **Backend**: Node.js, Express, `tsx` (TypeScript Execution), `undici` (`ProxyAgent` untuk transmisi proxy HTTP/HTTPS/SOCKS5), `node-cron`.
- **Bundler & Build**: Vite, esbuild (CommonJS server output untuk Cloud Run / container).

---

## 📦 Persyaratan Sistem

- **Node.js**: v18.0.0 atau lebih baru (direkomendasikan v20+)
- **NPM** atau **Bun**
- Sistem Operasi: Linux, macOS, Windows (native atau melalui WSL2)

---

## 💻 Panduan Instalasi & Menjalankan Aplikasi

### 📥 1. Klon Repositori (Git Clone)
Buka terminal Anda (misal di Home direktori `~`), lalu klon repositori dan masuk ke dalam folder proyek:
```bash
git clone https://github.com/rayzanzavio/cybersecurity-vulnerability-audit-scanner.git
cd cybersecurity-vulnerability-audit-scanner
```

---

### ⚡ 2. Cara Termudah: 1-Click Setup (Otomatis & Global)
Setelah masuk ke folder hasil git clone di atas, jalankan skrip setup berikut:
```bash
chmod +x setup.sh && ./setup.sh
```
Skrip ini akan secara otomatis:
1. Memasang seluruh dependensi tanpa konflik versi (`--legacy-peer-deps`).
2. Mendaftarkan perintah **`cyber-audit`** dan **`cyber-audit-web`** ke `/usr/local/bin` (PATH sistem).
3. **Kamu bisa langsung memanggilnya dari direktori mana saja (termasuk Home `~`) tanpa harus masuk ke folder git clone ini lagi!**

---

### 🛠 Cara Manual (Langkah demi Langkah)

#### 1. Klon Repositori & Masuk Folder
```bash
git clone https://github.com/rayzanzavio/cybersecurity-vulnerability-audit-scanner.git
cd cybersecurity-vulnerability-audit-scanner
```

#### 2. Pasang Dependensi
> **Catatan jika muncul error `npm ERR! code ERESOLVE`**:
> Error ini terjadi karena NPM versi baru memberlakukan pemeriksaan versi peer dependency yang ketat antara `vite` dan `esbuild`. Untuk mengatasinya, gunakan flag `--legacy-peer-deps`:
```bash
npm install --legacy-peer-deps
```
*(File `.npmrc` juga sudah disertakan dalam repositori ini agar `npm install` biasa otomatis mengabaikan konflik peer).*

#### 3. Jalankan Web GUI (Development)
```bash
npm run dev
```
Aplikasi akan aktif dan dapat diakses di peramban pada:
`http://localhost:3000`

#### 4. Memanggil dari Home Direktori (`~`) atau Mana Saja
Setelah menjalankan `./setup.sh`, kamu bisa membuka terminal di folder mana pun (misal di Home `~`):
- **Menyalakan Web GUI**:
  ```bash
  cyber-audit-web
  ```
- **Scan website target langsung dari terminal**:
  ```bash
  cyber-audit -u https://example.com
  ```
- **Scan daftar subdomain hasil recon di folder aktif**:
  ```bash
  cyber-audit -l subdomains.txt -x http://127.0.0.1:8080
  ```

#### 5. Build dan Jalankan untuk Produksi (Opsional)
```bash
npm run build
npm start
```

---

## 🖥 Panduan Penggunaan Antarmuka Web

1. **Pemindai Tunggal (Single Scanner)**:
   - Masukkan target URL (contoh: `https://example.com` atau `http://192.168.1.100:8080`).
   - Pilih template YAML yang ingin diaktifkan.
   - Klik **Mulai Audit Keamanan**.
   - Pantau eksekusi log secara langsung melalui panel *Live Auditor Terminal*.

2. **Pemindai Massal (Batch Scanner)**:
   - Buka tab **Batch (Subfinder)**.
   - Tarik dan lepas (*drag & drop*) file hasil recon (contoh: `subdomains.txt`) ke area upload.
   - Tentukan template dan proxy yang akan digunakan.
   - Klik **Jalankan Pemindaian Batch** untuk memindai seluruh subdomain secara berurutan.
   - Unduh laporan gabungan melalui tombol **Ekspor PDF Batch**.

3. **Pengaturan Proxy**:
   - Buka tab **Proxy Upstream**.
   - Pilih preset (Burp Suite, OWASP ZAP, atau Tor).
   - Klik **Uji Koneksi Tunnel Proxy** untuk memverifikasi latensi dan memeriksa IP publik keluar.

4. **Kustomisasi Tampilan**:
   - Klik tombol **`Visual: [Nama Tema]`** di pojok kanan atas atau buka tab **Sesuaikan Visual**.
   - Pilih tema warna, aksen, tipografi, kerapatan layar, efek scanline, dan suara interaktif sesuai kenyamanan Anda.

---

## 🐧 Panduan Integrasi Linux & WSL CLI

Aplikasi menyediakan skrip executable CLI portabel yang dapat diunduh langsung menggunakan perintah 1-baris (*one-liner*):

### Instalasi Otomatis (1-Liner)
```bash
# Menggunakan cURL
curl -fsSL http://localhost:3000/install.sh | bash

# Atau menggunakan Wget
wget -qO- http://localhost:3000/install.sh | bash
```

### Contoh Perintah Eksekusi CLI

1. **Audit Target Tunggal**:
   ```bash
   ./cyber-audit -u https://target.com
   ```

2. **Audit dengan Filter Tingkat Keparahan**:
   ```bash
   ./cyber-audit -u https://target.com -p critical
   ```

3. **Mengalirkan (*Piping*) Output Subfinder ke Scanner**:
   ```bash
   subfinder -d target.com -silent | tee subdomains.txt
   ./cyber-audit -l subdomains.txt -t owasp-security-headers -p high
   ```

4. **Merutekan Traffic CLI Melalui Burp Suite Pro**:
   ```bash
   ./cyber-audit -u https://target.com -x http://127.0.0.1:8080
   ```

5. **Pemasangan Cron Job Harian di Server Linux**:
   ```bash
   (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/cyber-audit -u https://target.com -p high >> /var/log/audit.log 2>&1") | crontab -
   ```

---

## 🔌 Konfigurasi Upstream Proxy (Burp Suite, ZAP, Tor)

| Perangkat Lunak | URL Proxy Standar | Catatan Konfigurasi |
| :--- | :--- | :--- |
| **Burp Suite Pro** | `http://127.0.0.1:8080` | Pastikan *Proxy Listeners* aktif pada tab *Proxy > Options*. Aktifkan *Bypass TLS Verification* jika menggunakan sertifikat default PortSwigger. |
| **OWASP ZAP** | `http://127.0.0.1:8081` | Atur ZAP di mode daemon atau desktop GUI pada port 8081. |
| **Tor Network** | `socks5://127.0.0.1:9050` | Pastikan service daemon Tor aktif (`sudo systemctl start tor`). |
| **Corporate HTTP** | `http://proxy.corp.internal:3128` | Mendukung otentikasi Basic Auth (username & password) serta spoofing User-Agent kustom. |

---

## 🧩 Sistem Ekstensi Keamanan (Extension Store)

Anda dapat memperluas kapabilitas audit dengan menginstal ekstensi kustom. Struktur manifest ekstensi berformat JSON:

```json
{
  "id": "my-custom-vuln-pack",
  "name": "Custom Organization Audit Pack",
  "version": "1.0.0",
  "author": "Security Engineering Team",
  "description": "Deteksi kerentanan khusus internal service & REST API gateway.",
  "category": "api",
  "templates": [
    {
      "id": "internal-actuator-leak",
      "name": "Spring Boot Actuator Env Leak",
      "severity": "high",
      "cvssScore": 7.5,
      "cweId": "CWE-200",
      "owaspCategory": "A01:2021-Broken Access Control",
      "description": "Mendeteksi endpoint /actuator/env yang terekspos ke publik.",
      "remediation": "Batasi akses actuator hanya ke jaringan internal.",
      "enabled": true,
      "rawYaml": "id: internal-actuator-leak\ninfo:\n  name: Spring Boot Actuator\n  severity: high\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/actuator/env\"\n    matchers:\n      - type: status\n        status:\n          - 200\n      - type: word\n        words:\n          - \"activeProfiles\"\n"
    }
  ]
}
```

---

## 🎨 Penyesuaian Visual & Audio (Visual Customizer)

Platform menyediakan kontrol visual mendalam untuk pengalaman kerja optimal bagi security auditor:

- **Theme Presets**: Switch 1-klik antara 7 skema palet profesional (Cyber Slate, Matrix Green, OLED Black, Red Team, Synthwave, Amber CRT, dan White Hat Lab).
- **Aksen Warna**: Cyan, Emerald, Amber, Crimson, Violet, dan Sky Blue.
- **Tipografi**: Pilihan font Monospace (untuk pembacaan log payload), Sans (keseimbangan), atau Vintage Retro VT320.
- **Kerapatan Tata Letak**: Kompak (memuat lebih banyak data audit per layar), Standar, atau Lega.
- **Efek Retro & Audio**: Scanlines monitor tabung CRT, dot matrix grid, dan audio mekanikal berbasis Web Audio API.
- **Auto-Persistence**: Preferensi visual disimpan secara otomatis di `localStorage` peramban.

---

## 📡 Dokumentasi REST API

| Method | Endpoint | Deskripsi |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Memeriksa status kesehatan server dan scheduler. |
| `GET` | `/api/templates` | Mendapatkan daftar seluruh template YAML yang terdaftar. |
| `POST` | `/api/templates` | Menambahkan atau memperbarui template YAML audit. |
| `POST` | `/api/scan` | Mengeksekusi audit kerentanan pada target tunggal. |
| `POST` | `/api/scan/batch` | Mengeksekusi audit batch pada daftar subdomain/hosts. |
| `GET` | `/api/proxy` | Mengambil konfigurasi upstream proxy yang aktif. |
| `POST` | `/api/proxy` | Memperbarui pengaturan proxy (URL, auth, bypass TLS). |
| `POST` | `/api/proxy/test` | Menguji koneksi tunnel proxy dan memeriksa IP keluar. |
| `GET` | `/api/extensions` | Mengambil katalog ekstensi keamanan. |
| `POST` | `/api/extensions/toggle` | Mengaktifkan/menonaktifkan modul ekstensi tertentu. |
| `POST` | `/api/extensions/install` | Memasang ekstensi baru melalui manifest JSON. |
| `GET` | `/api/webhook` | Mengambil pengaturan notifikasi webhook Discord/Slack. |
| `POST` | `/api/webhook/test` | Mengirim payload simulasi alert ke URL webhook. |
| `GET` | `/api/schedule` | Mengambil status jadwal pemindaian harian (cron). |
| `GET` | `/install.sh` | Mengunduh skrip installer CLI untuk Linux / WSL. |

---

## ⚖️ Disclaimer Etika Keamanan

> **PERINGATAN**: Perangkat lunak ini dirancang khusus untuk keperluan pengujian keamanan yang sah (*authorized penetration testing*), audit internal kepatuhan (*security compliance*), dan riset bug bounty resmi. Dilarang keras melakukan pemindaian tanpa izin tertulis dari pemilik sistem target. Penulis dan pengembang tidak bertanggung jawab atas penyalahgunaan atau kerusakan yang diakibatkan oleh penggunaan aplikasi ini.
