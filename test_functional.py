import pytest
import requests
import json
import os
import urllib3
from app_new import app, get_redis_client

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Konfigurasi test
BASE_URL = "https://localhost:5000"
TEST_IP = "1.1.1.1"  # IP test (Cloudflare DNS)
TEST_IP_MALICIOUS = "185.143.223.12"  # Contoh IP yang terdeteksi berbahaya

class TestFunctional:
    @pytest.fixture(scope="class")
    def setup(self):
        """Setup untuk functional testing"""
        # Pastikan direktori results ada
        os.makedirs("results", exist_ok=True)
        
        # Pastikan Redis berjalan
        redis_client = get_redis_client()
        if redis_client is None:
            pytest.skip("Redis tidak tersedia")
        
        # Bersihkan cache Redis
        redis_client.flushdb()
        
        yield
        
        # Cleanup setelah testing
        redis_client.flushdb()

    def test_1_redis_connection(self, setup):
        """Test koneksi Redis"""
        redis_client = get_redis_client()
        assert redis_client is not None
        assert redis_client.ping() is True

    def test_2_validate_ip_endpoint(self, setup):
        """Test endpoint validasi IP"""
        # Test dengan IP normal
        response = requests.post(
            f"{BASE_URL}/validate-ip",
            json={"ips": [TEST_IP]},
            verify=False
        )
        assert response.status_code == 200
        data = response.json()
        assert "hasil" in data
        assert len(data["hasil"]) == 1
        assert data["hasil"][0]["value"] == TEST_IP

        # Test dengan IP berbahaya
        response = requests.post(
            f"{BASE_URL}/validate-ip",
            json={"ips": [TEST_IP_MALICIOUS]},
            verify=False
        )
        assert response.status_code == 200
        data = response.json()
        assert data["hasil"][0]["conclusion"] in ["Berbahaya", "False Positive", "Tidak Berbahaya"]

    def test_3_csv_generation(self, setup):
        """Test pembuatan file CSV"""
        response = requests.post(
            f"{BASE_URL}/validate-ip",
            json={
                "ips": [TEST_IP, TEST_IP_MALICIOUS],
                "save_csv": True
            },
            verify=False
        )
        assert response.status_code == 200
        data = response.json()
        assert "file_csv" in data
        
        # Download file CSV
        csv_response = requests.get(
            f"{BASE_URL}/download-csv?filename={data['file_csv']}",
            verify=False
        )
        assert csv_response.status_code == 200
        assert "text/csv" in csv_response.headers["Content-Type"]

    def test_4_redis_caching(self, setup):
        """Test fungsi caching Redis"""
        redis_client = get_redis_client()
        
        # Hapus cache yang mungkin ada
        redis_client.delete(f"otx_ip:{TEST_IP}")
        redis_client.delete(f"misp_ip:{TEST_IP}")
        redis_client.delete(f"kaspersky_ip:{TEST_IP}")
        
        # Validasi IP pertama kali
        response1 = requests.post(
            f"{BASE_URL}/validate-ip",
            json={"ips": [TEST_IP]},
            verify=False
        )
        
        # Validasi IP kedua kali (seharusnya dari cache)
        response2 = requests.post(
            f"{BASE_URL}/validate-ip",
            json={"ips": [TEST_IP]},
            verify=False
        )
        
        # Verifikasi hasil sama
        assert response1.json()["hasil"] == response2.json()["hasil"]
        
        # Verifikasi cache ada
        assert redis_client.get(f"otx_ip:{TEST_IP}") is not None
        assert redis_client.get(f"misp_ip:{TEST_IP}") is not None
        assert redis_client.get(f"kaspersky_ip:{TEST_IP}") is not None

    def test_5_clear_cache(self, setup):
        """Test endpoint clear cache"""
        # Tambahkan data ke cache
        redis_client = get_redis_client()
        redis_client.setex(f"otx_ip:{TEST_IP}", 3600, "1")
        
        # Clear cache
        response = requests.post(f"{BASE_URL}/clear-cache", verify=False)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "sukses"
        
        # Verifikasi cache kosong
        assert redis_client.get(f"otx_ip:{TEST_IP}") is None

    def test_6_error_handling(self, setup):
        """Test penanganan error"""
        # Test dengan input tidak valid
        response = requests.post(
            f"{BASE_URL}/validate-ip",
            json={"invalid": "data"},
            verify=False
        )
        assert response.status_code == 400
        
        # Test dengan file tidak ada
        response = requests.get(
            f"{BASE_URL}/download-csv?filename=nonexistent.csv",
            verify=False
        )
        assert response.status_code == 404

    def test_7_telegram_integration(self, setup):
        """Test integrasi Telegram"""
        # Buat file CSV test
        test_filename = "test_telegram.csv"
        with open(f"results/{test_filename}", "w") as f:
            f.write("test,data\n")
        
        try:
            response = requests.get(
                f"{BASE_URL}/send-csv-to-telegram?filename={test_filename}",
                verify=False
            )
            assert response.status_code == 200
            data = response.json()
            assert "ok" in data
        finally:
            # Cleanup
            if os.path.exists(f"results/{test_filename}"):
                os.remove(f"results/{test_filename}")

if __name__ == "__main__":
    pytest.main(["-v", "test_functional.py"]) 