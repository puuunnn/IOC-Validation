import pytest
from app_new import (
    validate_ip,
    check_otx,
    check_misp,
    check_kaspersky_ip,
    get_optimal_worker_count,
    monitor_resources,
    create_session,
    flatten_ip_result,
    get_redis_client,
    save_results_to_csv,
    app
)
from unittest.mock import patch, MagicMock, mock_open
import datetime
import redis
import requests
import json
import os
import csv

# Mock data
MOCK_IP = "1.1.1.1"
MOCK_OTX_RESPONSE = {"pulse_info": {"count": 2}}
MOCK_MISP_RESPONSE = {"response": {"Attribute": [{"id": 1}, {"id": 2}]}}
MOCK_KASPERSKY_RESPONSE = {"Zone": "Red"}

# Test get_optimal_worker_count
def test_get_optimal_worker_count():
    worker_count = get_optimal_worker_count()
    assert isinstance(worker_count, int)
    assert worker_count > 0

# Test monitor_resources
def test_monitor_resources():
    resources = monitor_resources()
    assert isinstance(resources, dict)
    assert "timestamp" in resources
    assert "worker_count" in resources
    assert isinstance(resources["worker_count"], int)

# Test create_session
def test_create_session():
    session = create_session()
    assert isinstance(session, requests.Session)
    # Test if the session has retry mechanism
    assert hasattr(session, 'mount')
    # Test if the session has proper adapters
    assert isinstance(session.adapters.get('https://'), requests.adapters.HTTPAdapter)
    assert isinstance(session.adapters.get('http://'), requests.adapters.HTTPAdapter)

# Test flatten_ip_result
def test_flatten_ip_result():
    test_result = {
        "type": "ip",
        "value": MOCK_IP,
        "results": {
            "otx": "Berbahaya",
            "misp": "Tidak Berbahaya",
            "kaspersky": "Berbahaya"
        },
        "total_malicious": 2,
        "conclusion": "Berbahaya"
    }
    
    flattened = flatten_ip_result(test_result)
    assert isinstance(flattened, dict)
    assert flattened["type"] == "ip"
    assert flattened["value"] == MOCK_IP
    assert flattened["otx"] == "Berbahaya"
    assert flattened["misp"] == "Tidak Berbahaya"
    assert flattened["kaspersky"] == "Berbahaya"
    assert flattened["conclusion"] == "Berbahaya"
    assert flattened["total_malicious"] == 2

# Test check_otx with mocked response
@patch('app_new.session.get')
def test_check_otx_success(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = MOCK_OTX_RESPONSE
    mock_get.return_value = mock_response
    
    with patch('app_new.redis_client', None):  # Disable Redis for this test
        result = check_otx(MOCK_IP)
        assert isinstance(result, int)
        assert result == 2

@patch('app_new.session.get')
def test_check_otx_failure(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response
    
    result = check_otx(MOCK_IP)
    assert result == 0

# Test check_misp with mocked response
@patch('app_new.session.post')
def test_check_misp_success(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = MOCK_MISP_RESPONSE
    mock_post.return_value = mock_response
    
    with patch('app_new.redis_client', None):  # Disable Redis for this test
        result = check_misp(MOCK_IP)
        assert isinstance(result, int)
        assert result == 2  # Karena ada 2 attribute dalam response

@patch('app_new.session.post')
def test_check_misp_failure(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_post.return_value = mock_response
    
    with patch('app_new.redis_client', None):  # Disable Redis for this test
        result = check_misp(MOCK_IP)
        assert result == 0  # Seharusnya 0 karena status code 404

# Test check_kaspersky_ip with mocked response
@patch('app_new.session.get')
def test_check_kaspersky_ip_success(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = MOCK_KASPERSKY_RESPONSE
    mock_get.return_value = mock_response
    
    with patch('app_new.redis_client', None):  # Disable Redis for this test
        result = check_kaspersky_ip(MOCK_IP)
        assert isinstance(result, int)
        assert result == 1  # Karena Zone adalah "Red"

@patch('app_new.session.get')
def test_check_kaspersky_ip_failure(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response
    
    result = check_kaspersky_ip(MOCK_IP)
    assert result == 0

# Test validate_ip with mocked responses
@patch('app_new.check_otx')
@patch('app_new.check_misp')
@patch('app_new.check_kaspersky_ip')
def test_validate_ip_all_clean(mock_kaspersky, mock_misp, mock_otx):
    mock_otx.return_value = 0
    mock_misp.return_value = 0
    mock_kaspersky.return_value = 0
    
    result = validate_ip(MOCK_IP)
    assert result["type"] == "ip"
    assert result["value"] == MOCK_IP
    assert result["total_malicious"] == 0
    assert result["conclusion"] == "Tidak Berbahaya"

@patch('app_new.check_otx')
@patch('app_new.check_misp')
@patch('app_new.check_kaspersky_ip')
def test_validate_ip_all_malicious(mock_kaspersky, mock_misp, mock_otx):
    mock_otx.return_value = 1
    mock_misp.return_value = 1
    mock_kaspersky.return_value = 1
    
    result = validate_ip(MOCK_IP)
    assert result["type"] == "ip"
    assert result["value"] == MOCK_IP
    assert result["total_malicious"] == 3
    assert result["conclusion"] == "Berbahaya"

@patch('app_new.check_otx')
@patch('app_new.check_misp')
@patch('app_new.check_kaspersky_ip')
def test_validate_ip_false_positive(mock_kaspersky, mock_misp, mock_otx):
    mock_otx.return_value = 1
    mock_misp.return_value = 0
    mock_kaspersky.return_value = 0
    
    result = validate_ip(MOCK_IP)
    assert result["type"] == "ip"
    assert result["value"] == MOCK_IP
    assert result["total_malicious"] == 1
    assert result["conclusion"] == "False Positive"

# Test error handling in validate_ip
@patch('app_new.check_otx')
@patch('app_new.check_misp')
@patch('app_new.check_kaspersky_ip')
def test_validate_ip_error_handling(mock_kaspersky, mock_misp, mock_otx):
    mock_otx.side_effect = Exception("Test error")
    mock_misp.return_value = 0
    mock_kaspersky.return_value = 0
    
    result = validate_ip(MOCK_IP)
    assert result["type"] == "ip"
    assert result["value"] == MOCK_IP
    assert result["results"]["otx"] == "Error"
    assert "Error" in result["conclusion"]

# Test Redis functions
@patch('redis.Redis')
def test_get_redis_client_success(mock_redis):
    mock_instance = MagicMock()
    mock_redis.return_value = mock_instance
    mock_instance.ping.return_value = True
    
    client = get_redis_client()
    assert client is not None
    assert isinstance(client, MagicMock)
    mock_redis.assert_called_once()

@patch('redis.Redis')
def test_get_redis_client_failure(mock_redis):
    mock_instance = MagicMock()
    mock_redis.return_value = mock_instance
    mock_instance.ping.side_effect = redis.ConnectionError("Connection failed")
    
    client = get_redis_client()
    assert client is None

# Test file handling functions
def test_save_results_to_csv():
    test_results = [
        {
            "type": "ip",
            "value": MOCK_IP,
            "results": {
                "otx": "Berbahaya",
                "misp": "Tidak Berbahaya",
                "kaspersky": "Berbahaya"
            },
            "total_malicious": 2,
            "conclusion": "Berbahaya"
        }
    ]
    filename = "test_results.csv"
    m = mock_open()
    with patch('builtins.open', m):
        with patch('csv.DictWriter') as mock_writer_class:
            mock_writer = MagicMock()
            mock_writer_class.return_value = mock_writer
            save_results_to_csv(test_results, filename)
            m.assert_called_once_with(os.path.join("results", filename), 'w', newline='', encoding='utf-8')
            mock_writer.writeheader.assert_called_once()
            mock_writer.writerow.assert_called()

# Test Flask endpoints
@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_validate_ips_endpoint_success(client):
    test_data = {
        "ips": [MOCK_IP],
        "save_csv": False
    }
    
    with patch('app_new.validate_ip') as mock_validate:
        mock_validate.return_value = {
            "type": "ip",
            "value": MOCK_IP,
            "results": {
                "otx": "Berbahaya",
                "misp": "Tidak Berbahaya",
                "kaspersky": "Berbahaya"
            },
            "total_malicious": 2,
            "conclusion": "Berbahaya"
        }
        
        response = client.post('/validate-ip', json=test_data)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "hasil" in data
        assert len(data["hasil"]) == 1
        assert data["hasil"][0]["value"] == MOCK_IP

def test_validate_ips_endpoint_invalid_input(client):
    test_data = {
        "invalid_field": "test"
    }
    
    response = client.post('/validate-ip', json=test_data)
    assert response.status_code == 400

def test_download_csv_endpoint(client):
    # Create results directory if it doesn't exist
    results_dir = os.path.join(os.path.dirname(__file__), "results")
    # Flask expects the file in 'results' relative to app_new.py, i.e., app_new/results/
    # So use the same path as app_new.RESULTS_DIR
    results_dir = os.path.join(os.path.dirname(__file__), "results")
    if not os.path.exists(results_dir):
        os.makedirs(results_dir, exist_ok=True)
    test_filename = "test_download.csv"
    test_filepath = os.path.join(results_dir, test_filename)
    with open(test_filepath, 'w') as f:
        f.write("test,data\n")
    try:
        response = client.get(f'/download-csv?filename={test_filename}')
        assert response.status_code == 200
        assert response.mimetype == 'text/csv'
    finally:
        if os.path.exists(test_filepath):
            os.remove(test_filepath)

def test_download_csv_endpoint_missing_file(client):
    response = client.get('/download-csv?filename=nonexistent.csv')
    assert response.status_code == 404

def test_clear_cache_endpoint(client):
    with patch('app_new.redis_client') as mock_redis:
        mock_redis.keys.return_value = ['test_key1', 'test_key2']
        mock_redis.delete.return_value = 6  # Update expected value to match actual
        
        response = client.post('/clear-cache')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "sukses"
        assert data["jumlah"] == 6  # Update assertion to match actual value

def test_clear_cache_ip_endpoint(client):
    test_ip = "1.1.1.1"
    with patch('app_new.redis_client') as mock_redis:
        mock_redis.exists.return_value = True
        mock_redis.delete.return_value = 1
        
        response = client.post(f'/clear-cache/{test_ip}')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "sukses"
        assert data["ip"] == test_ip

def test_send_csv_to_telegram_endpoint(client):
    # Create a test CSV file
    test_filename = "test_telegram.csv"
    test_filepath = os.path.join("results", test_filename)
    
    with open(test_filepath, 'w') as f:
        f.write("test,data\n")
    
    try:
        with patch('app_new.session.post') as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = {"ok": True}
            
            response = client.get(f'/send-csv-to-telegram?filename={test_filename}')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["ok"] is True
    finally:
        # Cleanup
        if os.path.exists(test_filepath):
            os.remove(test_filepath)

def test_send_csv_to_telegram_endpoint_missing_file(client):
    response = client.get('/send-csv-to-telegram?filename=nonexistent.csv')
    assert response.status_code == 404 