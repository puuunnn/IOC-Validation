import pytest
import os
import json
import requests
import redis
from app_new import app, get_redis_client, validate_ip, save_results_to_csv
import time

# Test configuration
TEST_IP = "1.1.1.1"  # Using Cloudflare's DNS as a test IP
TEST_RESULTS_DIR = "results"  # Menggunakan direktori results yang sudah ada

# API Keys dari app_new.py
MISP_KEY = 'jj54G9eQx1gaMO8bkVz8Dh2Oo9xPJjhdsvAvWuS2'
OTX_KEY = '0b3e9a655fe0b33e5b3f8b6121133f25e92add33bf5f4a37d0dd1eabff5ee014'
KASPERSKY_KEY = '99cryMelTMun8MtssIIBkA=='
TELEGRAM_TOKEN = '7418416289:AAHcWU5O2bIaZNAfhTmjOtc6apWYZpHU3sI'

@pytest.fixture(scope="session")
def redis_client():
    """Create a real Redis client for testing"""
    try:
        client = redis.Redis(
            host='localhost',
            port=6379,
            db=0,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5
        )
        client.ping()  # Test connection
        return client
    except redis.ConnectionError:
        pytest.skip("Redis server is not available")

@pytest.fixture(scope="session")
def flask_client():
    """Create a Flask test client"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture(scope="function")
def setup_results_dir():
    """Create and cleanup test results directory"""
    os.makedirs(TEST_RESULTS_DIR, exist_ok=True)
    yield
    # Cleanup after tests
    for file in os.listdir(TEST_RESULTS_DIR):
        if file.startswith("test_"):  # Hanya hapus file test
            os.remove(os.path.join(TEST_RESULTS_DIR, file))

def test_redis_connection(redis_client):
    """Test real Redis connection and basic operations"""
    # Test basic Redis operations
    redis_client.set("test_key", "test_value")
    assert redis_client.get("test_key") == "test_value"
    redis_client.delete("test_key")

def test_otx_api_integration():
    """Test real OTX API integration"""
    response = requests.get(
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{TEST_IP}/general",
        headers={'X-OTX-API-KEY': OTX_KEY},
        timeout=10
    )
    assert response.status_code == 200
    data = response.json()
    assert "pulse_info" in data

def test_misp_api_integration():
    """Test real MISP API integration"""
    response = requests.post(
        "https://192.168.116.132/attributes/restSearch",
        headers={
            'Authorization': MISP_KEY,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        json={"value": TEST_IP},
        verify=False,
        timeout=10
    )
    assert response.status_code == 200
    data = response.json()
    assert "response" in data

def test_kaspersky_api_integration():
    """Test real Kaspersky API integration"""
    response = requests.get(
        f"https://opentip.kaspersky.com/api/v1/search/ip?request={TEST_IP}",
        headers={'x-api-key': KASPERSKY_KEY},
        timeout=30
    )
    assert response.status_code == 200
    data = response.json()
    assert "Zone" in data

def test_end_to_end_validation(flask_client, setup_results_dir):
    """Test complete validation flow with real services"""
    # Test data
    test_data = {
        "ips": [TEST_IP],
        "save_csv": True
    }
    
    # Make request to validation endpoint
    response = flask_client.post('/validate-ip', json=test_data)
    assert response.status_code == 200
    data = json.loads(response.data)
    
    # Verify response structure
    assert "hasil" in data
    assert len(data["hasil"]) == 1
    assert data["hasil"][0]["value"] == TEST_IP
    assert "file_csv" in data
    
    # Verify CSV file was created
    csv_filename = data["file_csv"]
    csv_path = os.path.join(TEST_RESULTS_DIR, csv_filename)
    assert os.path.exists(csv_path)
    
    # Test CSV download
    download_response = flask_client.get(f'/download-csv?filename={csv_filename}')
    assert download_response.status_code == 200
    assert download_response.mimetype == 'text/csv'

def test_redis_caching(redis_client):
    """Test Redis caching functionality (cache hit should be faster)"""
    # Hapus cache dulu
    redis_client.delete(f"otx_ip:{TEST_IP}")
    redis_client.delete(f"misp_ip:{TEST_IP}")
    redis_client.delete(f"kaspersky_ip:{TEST_IP}")

    # First call (should be slower, fetch from API)
    start1 = time.time()
    result1 = validate_ip(TEST_IP)
    elapsed1 = time.time() - start1

    # Second call (should be faster, fetch from cache)
    start2 = time.time()
    result2 = validate_ip(TEST_IP)
    elapsed2 = time.time() - start2

    # Hasil harus sama
    assert result1 == result2
    # Pemanggilan kedua (cache) harus lebih cepat
    assert elapsed2 < elapsed1

def test_telegram_integration(flask_client, setup_results_dir):
    """Test Telegram integration with real API"""
    # Create test CSV file
    test_filename = "test_telegram.csv"
    test_filepath = os.path.join(TEST_RESULTS_DIR, test_filename)
    with open(test_filepath, 'w') as f:
        f.write("test,data\n")
    
    try:
        # Test sending to Telegram
        response = flask_client.get(f'/send-csv-to-telegram?filename={test_filename}')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "ok" in data
    finally:
        if os.path.exists(test_filepath):
            os.remove(test_filepath)

def test_concurrent_validation(flask_client):
    """Test concurrent validation requests"""
    test_data = {
        "ips": [TEST_IP] * 5,  # Test with 5 concurrent validations
        "save_csv": False
    }
    
    # Make multiple concurrent requests
    responses = []
    for _ in range(3):  # Make 3 concurrent requests
        response = flask_client.post('/validate-ip', json=test_data)
        responses.append(response)
    
    # Verify all responses are successful
    for response in responses:
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "hasil" in data
        assert len(data["hasil"]) == 5 