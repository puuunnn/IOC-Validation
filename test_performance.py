import pytest
import requests
import json
import time
import os
import urllib3
import concurrent.futures
from app_new import app, get_redis_client, get_optimal_worker_count

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Konfigurasi test
BASE_URL = "https://localhost:5000"
TEST_IP = "1.1.1.1"  # IP test (Cloudflare DNS)
TEST_IP_MALICIOUS = "185.143.223.12"  # Contoh IP yang terdeteksi berbahaya

# Konfigurasi threshold performa
SINGLE_REQUEST_TIMEOUT = 7.0  # Meningkatkan timeout untuk single request
CONCURRENT_REQUEST_TIMEOUT = 30.0  # Timeout untuk concurrent requests
BULK_VALIDATION_TIMEOUT = 60.0  # Timeout untuk bulk validation
ERROR_RECOVERY_TIMEOUT = 10.0  # Timeout untuk error recovery

class TestPerformance:
    @pytest.fixture(scope="class")
    def setup(self):
        """Setup untuk performance testing"""
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

    def test_1_response_time_single_request(self, setup):
        """Test waktu respons untuk single request"""
        # Lakukan warm-up request
        requests.post(
            f"{BASE_URL}/validate-ip",
            json={"ips": [TEST_IP]},
            verify=False
        )
        
        # Test utama
        start_time = time.time()
        response = requests.post(
            f"{BASE_URL}/validate-ip",
            json={"ips": [TEST_IP]},
            verify=False
        )
        end_time = time.time()
        
        assert response.status_code == 200
        response_time = end_time - start_time
        print(f"\nWaktu respons single request: {response_time:.2f} detik")
        print(f"Threshold: {SINGLE_REQUEST_TIMEOUT} detik")
        assert response_time < SINGLE_REQUEST_TIMEOUT

    def test_2_concurrent_requests(self, setup):
        """Test handling request bersamaan"""
        num_requests = 10
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_requests) as executor:
            futures = [
                executor.submit(
                    requests.post,
                    f"{BASE_URL}/validate-ip",
                    json={"ips": [TEST_IP]},
                    verify=False
                )
                for _ in range(num_requests)
            ]
            responses = [f.result() for f in futures]
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Verifikasi semua request berhasil
        for response in responses:
            assert response.status_code == 200
        
        print(f"\nWaktu total untuk {num_requests} request bersamaan: {total_time:.2f} detik")
        print(f"Rata-rata waktu per request: {total_time/num_requests:.2f} detik")
        print(f"Threshold: {CONCURRENT_REQUEST_TIMEOUT} detik")
        assert total_time < CONCURRENT_REQUEST_TIMEOUT

    def test_3_bulk_ip_validation(self, setup):
        """Test validasi banyak IP sekaligus"""
        # Buat list IP untuk testing
        test_ips = [TEST_IP] * 50  # 50 IP untuk testing
        
        start_time = time.time()
        response = requests.post(
            f"{BASE_URL}/validate-ip",
            json={"ips": test_ips},
            verify=False
        )
        end_time = time.time()
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["hasil"]) == len(test_ips)
        
        total_time = end_time - start_time
        print(f"\nWaktu validasi {len(test_ips)} IP: {total_time:.2f} detik")
        print(f"Rata-rata waktu per IP: {total_time/len(test_ips):.2f} detik")
        print(f"Threshold: {BULK_VALIDATION_TIMEOUT} detik")
        assert total_time < BULK_VALIDATION_TIMEOUT

    def test_4_cache_performance(self, setup):
        """Test performa dengan dan tanpa cache"""
        redis_client = get_redis_client()
        
        # Hapus cache yang mungkin ada
        redis_client.delete(f"otx_ip:{TEST_IP}")
        redis_client.delete(f"misp_ip:{TEST_IP}")
        redis_client.delete(f"kaspersky_ip:{TEST_IP}")
        
        # Test tanpa cache
        start_time_no_cache = time.time()
        response1 = requests.post(
            f"{BASE_URL}/validate-ip",
            json={"ips": [TEST_IP]},
            verify=False
        )
        time_no_cache = time.time() - start_time_no_cache
        
        # Test dengan cache
        start_time_with_cache = time.time()
        response2 = requests.post(
            f"{BASE_URL}/validate-ip",
            json={"ips": [TEST_IP]},
            verify=False
        )
        time_with_cache = time.time() - start_time_with_cache
        
        assert response1.status_code == 200
        assert response2.status_code == 200
        
        print(f"\nWaktu tanpa cache: {time_no_cache:.2f} detik")
        print(f"Waktu dengan cache: {time_with_cache:.2f} detik")
        print(f"Percepatan: {time_no_cache/time_with_cache:.2f}x")
        
        # Verifikasi bahwa waktu dengan cache lebih cepat
        assert time_with_cache < time_no_cache

    def test_5_resource_utilization(self, setup):
        """Test penggunaan resource saat validasi"""
        # Test dengan jumlah worker yang optimal
        optimal_workers = get_optimal_worker_count()
        print(f"\nJumlah worker optimal: {optimal_workers}")
        
        # Test dengan jumlah IP yang sesuai dengan worker
        test_ips = [TEST_IP] * optimal_workers
        
        start_time = time.time()
        response = requests.post(
            f"{BASE_URL}/validate-ip",
            json={"ips": test_ips},
            verify=False
        )
        end_time = time.time()
        
        assert response.status_code == 200
        data = response.json()
        assert "sumber_daya" in data
        
        total_time = end_time - start_time
        print(f"Waktu validasi dengan {optimal_workers} worker: {total_time:.2f} detik")
        print(f"Resource usage: {json.dumps(data['sumber_daya'], indent=2)}")
        
        # Verifikasi bahwa waktu validasi masuk akal
        assert total_time < CONCURRENT_REQUEST_TIMEOUT

    def test_6_error_recovery(self, setup):
        """Test performa saat recovery dari error"""
        # Test dengan IP yang tidak valid
        invalid_ips = ["invalid_ip"] * 10
        
        start_time = time.time()
        response = requests.post(
            f"{BASE_URL}/validate-ip",
            json={"ips": invalid_ips},
            verify=False
        )
        end_time = time.time()
        
        assert response.status_code == 200
        total_time = end_time - start_time
        
        print(f"\nWaktu recovery dari {len(invalid_ips)} error: {total_time:.2f} detik")
        print(f"Threshold: {ERROR_RECOVERY_TIMEOUT} detik")
        assert total_time < ERROR_RECOVERY_TIMEOUT

if __name__ == "__main__":
    pytest.main(["-v", "test_performance.py"]) 