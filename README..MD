# Validasi IP

Aplikasi Flask untuk validasi alamat IP menggunakan beberapa layanan threat intelligence seperti OTX, MISP, dan Kaspersky.

## Fitur

- Validasi IP dari berbagai sumber threat intelligence
- Caching hasil dengan Redis
- Export hasil ke CSV
- Integrasi dengan Telegram
- API RESTful

## Cara Menjalankan

### Menggunakan Docker Compose

```bash
docker-compose up -d


## 2. Persiapan GitHub Actions untuk CI/CD

Buat direktori `.github/workflows` di dalam direktori proyek Anda:

```bash
mkdir -p .github/workflows