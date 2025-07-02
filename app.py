import threading
import datetime
import requests
import urllib3
from flask import Flask, request, jsonify, send_file, render_template
from concurrent.futures import ThreadPoolExecutor
import os
import csv
import multiprocessing
import time
import logging
from logging.handlers import RotatingFileHandler
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import redis
import json
import traceback
import glob
import sqlite3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Buat direktori logs jika belum ada
LOGS_DIR = "logs"
os.makedirs(LOGS_DIR, exist_ok=True)

# Konfigurasi logging dasar
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # Log ke console
        RotatingFileHandler(
            os.path.join(LOGS_DIR, 'app.log'),
            maxBytes=10*1024*1024,
            backupCount=5
        )
    ]
)

logger = logging.getLogger(__name__)

# Kunci API
MISP_KEY = 'jj54G9eQx1gaMO8bkVz8Dh2Oo9xPJjhdsvAvWuS2'
OTX_KEY = '0b3e9a655fe0b33e5b3f8b6121133f25e92add33bf5f4a37d0dd1eabff5ee014'
KASPERSKY_KEY = '99cryMelTMun8MtssIIBkA=='

# Konfigurasi Telegram
TELEGRAM_TOKEN = '7418416289:AAHcWU5O2bIaZNAfhTmjOtc6apWYZpHU3sI'
CHAT_ID = '-4795617614'

# Konfigurasi Redis
REDIS_HOST = 'redis'  # Menggunakan nama service dari docker-compose
REDIS_PORT = 6379
REDIS_DB = 0
CACHE_TTL = 86400  # 24 jam dalam detik

# Inisialisasi Redis client dengan retry mechanism
def get_redis_client():
    retry_count = 0
    max_retries = 5
    while retry_count < max_retries:
        try:
            client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                db=REDIS_DB,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5
            )
            # Test koneksi
            client.ping()
            return client
        except redis.ConnectionError as e:
            retry_count += 1
            logger.warning(f"Gagal terhubung ke Redis (attempt {retry_count}/{max_retries}): {e}")
            time.sleep(2)  # Tunggu 2 detik sebelum mencoba lagi
    logger.error("Tidak dapat terhubung ke Redis setelah beberapa percobaan")
    return None

# Inisialisasi Redis client
redis_client = get_redis_client()

def get_optimal_worker_count():
    cpu_count = multiprocessing.cpu_count()
    return (2 * cpu_count) + 1

def monitor_resources():
    # Fungsi sederhana untuk monitoring waktu
    return {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "worker_count": get_optimal_worker_count()
    }

# Konfigurasi koneksi pooling
def create_session():
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=get_optimal_worker_count(),
        pool_maxsize=get_optimal_worker_count()
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

# Buat sesi global
session = create_session()

app = Flask(__name__)

RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)
DB_PATH = os.path.join(RESULTS_DIR, "history.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS validation_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            destination_ip TEXT,
            country TEXT,
            rule TEXT,
            severity TEXT,
            module TEXT,
            timestamp TEXT,
            value TEXT,
            type TEXT,
            otx TEXT,
            misp TEXT,
            kaspersky TEXT,
            total_malicious INTEGER,
            conclusion TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_validation_results(results):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    for r in results:
        c.execute("""
            INSERT INTO validation_history (
                source_ip, destination_ip, country, rule, severity, module, timestamp,
                value, type, otx, misp, kaspersky, total_malicious, conclusion
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            r.get("source_ip"),
            r.get("destination_ip"),
            r.get("country"),
            r.get("rule"),
            r.get("severity"),
            r.get("module"),
            r.get("timestamp"),
            r.get("value"),
            r.get("type"),
            r.get("results", {}).get("otx"),
            r.get("results", {}).get("misp"),
            r.get("results", {}).get("kaspersky"),
            r.get("total_malicious"),
            r.get("conclusion")
        ))
    conn.commit()
    conn.close()

def fetch_all_history():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
     # Ubah urutan menjadi timestamp DESC agar data terbaru muncul paling atas
    c.execute("SELECT source_ip, destination_ip, country, rule, severity, module, timestamp, value, type, otx, misp, kaspersky, total_malicious, conclusion FROM validation_history ORDER BY timestamp DESC, id DESC")
    rows = c.fetchall()
    conn.close()
    results = []
    parsed_ips = []
    for row in rows:
        result = {
            "source_ip": row[0],
            "destination_ip": row[1],
            "country": row[2],
            "rule": row[3],
            "severity": row[4],
            "module": row[5],
            "timestamp": row[6],
            "value": row[7],
            "type": row[8],
            "results": {
                "otx": row[9],
                "misp": row[10],
                "kaspersky": row[11]
            },
            "total_malicious": row[12],
            "conclusion": row[13]
        }
        results.append(result)
        parsed_ips.append({
            "value": row[7],
            "results": {
                "otx": row[9],
                "misp": row[10],
                "kaspersky": row[11]
            },
            "total_malicious": row[12],
            "conclusion": row[13]
        })
    return results, parsed_ips

# Inisialisasi DB saat startup
init_db()

def check_otx(ip):
    # Cek cache terlebih dahulu
    if redis_client is None:
        logger.warning("Redis tidak tersedia, melewati cache")
        return check_otx_direct(ip)
        
    cache_key = f"otx_ip:{ip}"
    try:
        cached_result = redis_client.get(cache_key)
        
        if cached_result is not None:
            logger.info(f"[OTX IP] Menggunakan hasil cache untuk IP {ip}")
            return int(cached_result)
    except redis.RedisError as e:
        logger.error(f"Kesalahan saat mengakses Redis: {e}")
        return check_otx_direct(ip, cache_key)
    
    return check_otx_direct(ip, cache_key)

def check_otx_direct(ip, cache_key=None):
    headers = {'X-OTX-API-KEY': OTX_KEY}
    try:
        r = session.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general", 
                       headers=headers, 
                       timeout=10)
        if r.status_code == 200:
            data = r.json()
            pulse_count = data['pulse_info']['count']
            result = 2 if pulse_count > 30 else 1 if pulse_count > 0 else 0  # Perhitungan skor OTX
            
            # Simpan hasil ke cache jika Redis tersedia dan cache_key ada
            if redis_client is not None and cache_key is not None:
                try:
                    redis_client.setex(cache_key, CACHE_TTL, str(result))
                    logger.info(f"[OTX IP] Hasil baru disimpan ke cache untuk IP {ip}")
                except redis.RedisError as e:
                    logger.error(f"Kesalahan saat menyimpan ke Redis: {e}")
            
            return result
    except Exception as e:
        logger.error(f"[OTX IP] Kesalahan untuk IP {ip}: {e}")
    return 0

def check_misp(ip):
    # Cek cache terlebih dahulu
    if redis_client is None:
        logger.warning("Redis tidak tersedia, melewati cache")
        return check_misp_direct(ip)
        
    cache_key = f"misp_ip:{ip}"
    try:
        cached_result = redis_client.get(cache_key)
        
        if cached_result is not None:
            logger.info(f"[MISP IP] Menggunakan hasil cache untuk IP {ip}")
            return int(cached_result)
    except redis.RedisError as e:
        logger.error(f"Kesalahan saat mengakses Redis: {e}")
        return check_misp_direct(ip, cache_key)
    
    return check_misp_direct(ip, cache_key)

def check_misp_direct(ip, cache_key=None):
    headers = {'Authorization': MISP_KEY, 'Accept': 'application/json', 'Content-Type': 'application/json'}
    try:
        r = session.post("https://192.168.116.132/attributes/restSearch", 
                        headers=headers, 
                        json={"value": ip}, 
                        verify=False, 
                        timeout=10)
        if r.status_code == 200:
            attributes = r.json().get('response', {}).get('Attribute', [])
            result = 2 if len(attributes) > 0 else 0  # Perhitungan skor MISP
            
            # Simpan hasil ke cache jika Redis tersedia dan cache_key ada
            if redis_client is not None and cache_key is not None:
                try:
                    redis_client.setex(cache_key, CACHE_TTL, str(result))
                    logger.info(f"[MISP IP] Hasil baru disimpan ke cache untuk IP {ip}")
                except redis.RedisError as e:
                    logger.error(f"Kesalahan saat menyimpan ke Redis: {e}")
            
            return result
    except Exception as e:
        logger.error(f"[MISP IP] Kesalahan untuk IP {ip}: {e}")
    return 0

def check_kaspersky_ip(ip):
    # Cek cache terlebih dahulu
    if redis_client is None:
        logger.warning("Redis tidak tersedia, melewati cache")
        return check_kaspersky_ip_direct(ip)
        
    cache_key = f"kaspersky_ip:{ip}"
    try:
        cached_result = redis_client.get(cache_key)
        
        if cached_result is not None:
            logger.info(f"[Kaspersky IP] Menggunakan hasil cache untuk IP {ip}")
            return int(cached_result)
    except redis.RedisError as e:
        logger.error(f"Kesalahan saat mengakses Redis: {e}")
        return check_kaspersky_ip_direct(ip, cache_key)
    
    return check_kaspersky_ip_direct(ip, cache_key)

def check_kaspersky_ip_direct(ip, cache_key=None):
    headers = {'x-api-key': KASPERSKY_KEY}
    try:
        r = session.get(
            f"https://opentip.kaspersky.com/api/v1/search/ip?request={ip}",
            headers=headers,
            timeout=30
        )
        if r.status_code == 200:
            data = r.json()
            zone = data.get('Zone')
            result = 2 if zone == 'Red' else 1 if zone == 'Orange' else 0  # Perhitungan skor Kaspersky
            
            # Simpan hasil ke cache jika Redis tersedia dan cache_key ada
            if redis_client is not None and cache_key is not None:
                try:
                    redis_client.setex(cache_key, CACHE_TTL, str(result))
                    logger.info(f"[Kaspersky IP] Hasil baru disimpan ke cache untuk IP {ip}")
                except redis.RedisError as e:
                    logger.error(f"Kesalahan saat menyimpan ke Redis: {e}")
            
            return result
    except Exception as e:
        logger.error(f"[Kaspersky IP] Kesalahan untuk IP {ip}: {e}")
    return 0

def malicious_status(score):
    if score == 2:
        return "Berbahaya"
    elif score == 1:
        return "Sedang (Mungkin Berbahaya)"
    else:
        return "Tidak Berbahaya"

def validate_ip(ip):
    try:
        otx_malicious = check_otx(ip)  # 0, 1, atau 2 berdasarkan jumlah pulses
        misp_malicious = check_misp(ip)  # 0 atau 2 jika ditemukan
        kaspersky_malicious = check_kaspersky_ip(ip)  # 0, 1, atau 2 berdasarkan zona

        # Hitung total malicious berdasarkan skor baru
        total_malicious = otx_malicious + misp_malicious + kaspersky_malicious
        conclusion = "Berbahaya" if total_malicious >= 2 else "Sedang (Mungkin Berbahaya)" if total_malicious == 1 else "Tidak Berbahaya"

        return {
            "type": "ip",
            "value": ip,
            "results": {
                "otx": malicious_status(otx_malicious),
                "misp": malicious_status(misp_malicious),
                "kaspersky": malicious_status(kaspersky_malicious)
            },
            "total_malicious": total_malicious,
            "conclusion": conclusion
        }
    except Exception as e:
        logger.error(f"[Validasi IP] Kesalahan untuk IP {ip}: {e}")
        return {
            "type": "ip",
            "value": ip,
            "results": {
                "otx": "Error",
                "misp": "Error",
                "kaspersky": "Error"
            },
            "total_malicious": 0,
            "conclusion": f"Error: {str(e)}"
        }

@app.route('/validate-ip', methods=['POST'])
def validate_ips():
    try:
        # Log request details
        logger.info(f"Received request from: {request.remote_addr}")
        logger.info(f"Request headers: {dict(request.headers)}")
        logger.info(f"Request method: {request.method}")
        
        # Handle different content types and input formats
        try:
            if request.is_json:
                data = request.get_json(force=True)
            else:
                # Try to get raw data and parse it
                raw_data = request.get_data(as_text=True)
                logger.info(f"Raw data received: {raw_data}")
                
                # Handle potential string formatting issues
                if isinstance(raw_data, str):
                    # Remove any potential BOM or special characters
                    raw_data = raw_data.strip().strip('\ufeff')
                    # Try to parse as JSON
                    data = json.loads(raw_data)
                else:
                    data = raw_data
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {str(e)}")
            return jsonify({"error": "Invalid JSON format", "details": str(e)}), 400
        except Exception as e:
            logger.error(f"Error parsing request data: {str(e)}")
            return jsonify({"error": "Error parsing request data", "details": str(e)}), 400
        
        logger.info(f"Parsed data: {data}")
        
        if not data:
            return jsonify({"error": "No data received"}), 400
            
        # Handle both 'entries' and 'ips' field names
        entries = data.get('entries') or data.get('ips', [])
        if isinstance(entries, str):
            try:
                entries = json.loads(entries)
            except json.JSONDecodeError:
                return jsonify({"error": "Invalid entries format"}), 400
                
        save_csv = data.get('save_csv', False)
        
        if not entries or not isinstance(entries, list):
            return jsonify({"error": "Field 'entries' harus berupa list"}), 400
        
        # Validasi setiap entry
        for entry in entries:
            if not isinstance(entry, dict):
                return jsonify({"error": "Setiap entry harus berupa object"}), 400
            if not entry.get("source_ip"):
                return jsonify({"error": "Field 'source_ip' wajib ada di setiap entry"}), 400
        
        pre_validation_resources = monitor_resources()
        logger.info(f"Sumber daya sebelum validasi: {pre_validation_resources}")
        
        start_time = time.time()
        logger.info(f"Memulai validasi {len(entries)} IP dengan {get_optimal_worker_count()} worker")
        
        def process_entry(entry):
            try:
                ip = entry.get("source_ip")
                logger.info(f"Processing IP: {ip}")
                result = validate_ip(ip)
                # Tambahkan metadata ke hasil
                result.update({
                    "source_ip": entry.get("source_ip"),
                    "destination_ip": entry.get("destination_ip"),
                    "rule": entry.get("rule"),
                    "timestamp": entry.get("timestamp"),
                    "country": entry.get("country"),
                    "severity": entry.get("severity"),
                    "module": entry.get("module")
                })
                return result
            except Exception as e:
                logger.error(f"Error processing entry: {e}")
                return {
                    "error": str(e),
                    "source_ip": entry.get("source_ip"),
                    "destination_ip": entry.get("destination_ip")
                }
        
        with ThreadPoolExecutor(max_workers=get_optimal_worker_count()) as executor:
            results = list(executor.map(process_entry, entries))
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        post_validation_resources = monitor_resources()
        logger.info(f"Sumber daya setelah validasi: {post_validation_resources}")
        logger.info(f"Validasi selesai dalam {processing_time:.2f} detik")
        
        response_data = {
            "success": True,
            "hasil": results,
            "waktu_pemrosesan": f"{processing_time:.2f} detik",
            "jumlah_worker": get_optimal_worker_count(),
            "sumber_daya": {
                "sebelum_validasi": pre_validation_resources,
                "setelah_validasi": post_validation_resources
            }
        }
        
        if save_csv:
            filename = f"validasi_ip_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            save_results_to_csv(results, filename)
            response_data["file_csv"] = filename

        # Simpan ke database
        insert_validation_results(results)

        logger.info(f"Sending response: {response_data}")
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error in validate_ips: {str(e)}")
        logger.error(f"Error details: {traceback.format_exc()}")
        return jsonify({
            "success": False,
            "error": f"Terjadi kesalahan: {str(e)}",
            "details": traceback.format_exc()
        }), 500

@app.route('/download-csv', methods=['GET'])
def download_csv():
    filename = request.args.get('filename')
    if not filename:
        return jsonify({"error": "Parameter 'filename' tidak ditemukan"}), 400
    
    file_path = os.path.join(RESULTS_DIR, filename)
    if not os.path.exists(file_path):
        return jsonify({"error": "File tidak ditemukan"}), 404
    
    return send_file(file_path, as_attachment=True)

@app.route('/send-csv-to-telegram', methods=['GET'])
def send_csv_to_telegram():
    filename = request.args.get('filename')
    if not filename:
        return jsonify({"error": "Parameter 'filename' tidak ditemukan"}), 400
    
    file_path = os.path.join(RESULTS_DIR, filename)
    if not os.path.exists(file_path):
        return jsonify({"error": "File tidak ditemukan"}), 404
    
    try:
        url = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument'
        with open(file_path, 'rb') as file:
            response = session.post(
                url,
                data={"chat_id": CHAT_ID},
                files={"document": file}
            )
        
        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            return jsonify({"error": f"Gagal mengirim ke Telegram: {response.text}"}), 500
            
    except Exception as e:
        return jsonify({"error": f"Gagal mengirim file ke Telegram: {str(e)}"}), 500

def save_results_to_csv(results, filename):
    if not results:
        return
    flat_results = [flatten_ip_result(r) for r in results]
    keys = flat_results[0].keys()
    with open(os.path.join(RESULTS_DIR, filename), 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for row in flat_results:
            writer.writerow(row)

def flatten_ip_result(r):
    return {
        "value": r["value"],
        "type": r["type"],
        "results": r["results"],
        "total_malicious": r["total_malicious"],
        "source_ip": r.get("source_ip"),
        "destination_ip": r.get("destination_ip"),
        "rule": r.get("rule"),
        "severity": r.get("severity"),
        "timestamp": r.get("timestamp"),
        "conclusion": r["conclusion"],
        "country": r.get("country"),
        "module": r.get("module")
    }

def clear_cache_example():
    """
    Contoh penggunaan curl untuk menghapus cache:
    
    1. Hapus semua cache:
    curl -X POST -k https://localhost:5000/clear-cache
    
    2. Hapus cache untuk IP spesifik:
    curl -X POST -k https://localhost:5000/clear-cache/1.2.3.4
    
    Catatan: 
    - Gunakan -k untuk mengabaikan verifikasi SSL
    - Ganti localhost dengan IP server Anda
    """
    pass

@app.route('/clear-cache', methods=['POST'])
def clear_cache():
    try:
        if redis_client is None:
            return jsonify({"error": "Redis tidak tersedia"}), 503

        # Hapus semua cache yang berhubungan dengan validasi
        keys = redis_client.keys("kaspersky_ip:*") + redis_client.keys("misp_ip:*") + redis_client.keys("otx_ip:*")
        if keys:
            redis_client.delete(*keys)
            logger.info(f"Cache berhasil dihapus: {len(keys)} kunci")
            return jsonify({
                "status": "sukses",
                "pesan": f"Cache berhasil dihapus: {len(keys)} kunci",
                "jumlah": len(keys)
            })
        else:
            return jsonify({
                "status": "sukses",
                "pesan": "Tidak ada cache yang perlu dihapus",
                "jumlah": 0
            })
    except Exception as e:
        logger.error(f"Kesalahan saat menghapus cache: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/clear-cache/<ip>', methods=['POST'])
def clear_cache_ip(ip):
    try:
        if redis_client is None:
            return jsonify({"error": "Redis tidak tersedia"}), 503

        cache_keys = [
            f"kaspersky_ip:{ip}",
            f"misp_ip:{ip}",
            f"otx_ip:{ip}"
        ]
        
        deleted_keys = []
        for key in cache_keys:
            if redis_client.exists(key):
                redis_client.delete(key)
                deleted_keys.append(key)
        
        if deleted_keys:
            logger.info(f"Cache untuk IP {ip} berhasil dihapus: {deleted_keys}")
            return jsonify({
                "status": "sukses",
                "pesan": f"Cache untuk IP {ip} berhasil dihapus",
                "ip": ip,
                "kunci_terhapus": deleted_keys
            })
        else:
            return jsonify({
                "status": "sukses",
                "pesan": f"Tidak ada cache untuk IP {ip}",
                "ip": ip
            })
    except Exception as e:
        logger.error(f"Kesalahan saat menghapus cache untuk IP {ip}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/clear-db', methods=['POST'])
def clear_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM validation_history")
        conn.commit()
        conn.close()
        logger.info("Seluruh data di database berhasil dihapus")
        return jsonify({"status": "sukses", "pesan": "Seluruh data di database berhasil dihapus"})
    except Exception as e:
        logger.error(f"Kesalahan saat menghapus database: {e}")
        return jsonify({"error": str(e)}), 500

"""
Contoh request untuk menghapus seluruh data history database:

1. Hapus seluruh data history:
   curl -X POST http://localhost:5000/clear-db

Catatan:
- Ganti `localhost` dengan alamat server Anda jika perlu.
- Endpoint ini akan menghapus semua data pada database history.db.
"""

def get_latest_csv_data():
    """
    Membaca data dari database history.db (bukan dari CSV)
    Menghapus data duplikat berdasarkan seluruh field.
    """
    try:
        results, parsed_ips = fetch_all_history()
        if not results:
            logger.info("Tidak ada data di database history.db")
            return [], []
        # Hapus duplikat berdasarkan seluruh field
        seen = set()
        unique_results = []
        for r in results:
            # Serialisasi seluruh dict untuk deteksi duplikat
            r_serialized = json.dumps(r, sort_keys=True)
            if r_serialized not in seen:
                seen.add(r_serialized)
                unique_results.append(r)
        logger.info(f"Berhasil memuat {len(unique_results)} record unik dari database")
        # parsed_ips juga perlu di-filter jika ingin konsisten
        seen_ips = set()
        unique_parsed_ips = []
        for p in parsed_ips:
            p_serialized = json.dumps(p, sort_keys=True)
            if p_serialized not in seen_ips:
                seen_ips.add(p_serialized)
                unique_parsed_ips.append(p)
        return unique_results, unique_parsed_ips
    except Exception as e:
        logger.error(f"Error membaca database: {e}")
        return [], []

def get_threat_status(value):
    """Konversi nilai numerik ke status threat"""
    try:
        num_val = int(value) if value else 0
        return "Berbahaya" if num_val > 0 else "Tidak Berbahaya"
    except:
        return "Tidak Berbahaya"

def map_conclusion(conclusion):
    """Map conclusion dari format lama ke format baru"""
    conclusion = conclusion.lower()
    if 'malicious' in conclusion or 'berbahaya' in conclusion:
        return "Berbahaya"
    elif 'false' in conclusion or 'positive' in conclusion:
        return "False Positive"
    else:
        return "Tidak Berbahaya"

def get_country_from_ratings(ratings):
    """Extract country info dari field ratings atau return default"""
    if ratings and 'tinggi' in ratings.lower():
        return "High Risk Country"
    return "Tidak Diketahui"

def get_severity_from_conclusion(conclusion):
    """Tentukan severity berdasarkan conclusion"""
    if conclusion == "Berbahaya":
        return "high"
    elif conclusion == "False Positive":
        return "medium"
    else:
        return "low"

def get_dashboard_stats(results):
    """Menghitung statistik untuk dashboard"""
    try:
        stats = {
            "total_alerts": len(results),
            "malicious_ips": len([r for r in results if r["conclusion"] == "Berbahaya"]),
            "false_positive": len([r for r in results if r["conclusion"] == "False Positive"]),
            "safe_ips": len([r for r in results if r["conclusion"] == "Tidak Berbahaya"])
        }
        return stats
    except Exception as e:
        logger.error(f"Error menghitung statistik: {e}")
        return {
            "total_alerts": 0,
            "malicious_ips": 0,
            "false_positive": 0,
            "safe_ips": 0
        }

@app.route('/')
def dashboard():
    """Dashboard dengan data real dari CSV"""
    try:
        # Baca data dari database
        results, parsed_ips = get_latest_csv_data()
        
        # Hitung statistik
        stats = get_dashboard_stats(results)
        
        return render_template('dashboard.html', 
                             results=results, 
                             parsed_ips=parsed_ips,
                             stats=stats,
                             last_updated=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
    except Exception as e:
        logger.error(f"Error dalam dashboard: {e}")
        return render_template('dashboard.html', 
                             results=[],
                             parsed_ips=[],
                             stats={"total_alerts": 0, "malicious_ips": 0, "false_positive": 0, "safe_ips": 0},
                             last_updated="Error - tidak ada data")

@app.route('/api/dashboard-data')
def api_dashboard_data():
    """API endpoint untuk mendapatkan data dashboard terbaru (untuk AJAX)"""
    try:
        results, parsed_ips = get_latest_csv_data()
        
        stats = get_dashboard_stats(results)
        
        return jsonify({
            "success": True,
            "results": results,
            "parsed_ips": parsed_ips,
            "stats": stats,
            "last_updated": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except Exception as e:
        logger.error(f"Error dalam API dashboard data: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

   
if __name__ == '__main__':
    logger.info("Aplikasi dimulai...")
    logger.info(f"Direktori logs: {os.path.abspath(LOGS_DIR)}")
    logger.info(f"Jumlah worker optimal: {get_optimal_worker_count()}")
    logger.info(f"Folder results: {os.path.abspath(RESULTS_DIR)}")
    # Hapus ssl_context untuk akses HTTP biasa
    app.run(host='0.0.0.0', port=5000, debug=True)

