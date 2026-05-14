"""
Pytest configuration and fixtures for JWT Cryptanalysis project
"""

import pytest
import json
import requests
from pathlib import Path
from core.jwt_config import BACKENDS, TEST_CREDENTIALS, PROJECT_ROOT

@pytest.fixture(scope="session")
def project_root():
    """Get project root directory"""
    return PROJECT_ROOT

@pytest.fixture
def vulnerable_backend():
    """Get vulnerable backend configuration"""
    return BACKENDS["vulnerable"]

@pytest.fixture
def secure_backend():
    """Get secure backend configuration"""
    return BACKENDS["secure"]

@pytest.fixture
def test_credentials():
    """Get test credentials"""
    return TEST_CREDENTIALS

@pytest.fixture
def admin_credentials():
    """Get admin test credentials"""
    return TEST_CREDENTIALS["admin"]

@pytest.fixture
def librarian_credentials():
    """Get librarian test credentials"""
    return TEST_CREDENTIALS["librarian"]

@pytest.fixture
def vulnerable_jwt_token(vulnerable_backend, admin_credentials):
    """
    Get a valid JWT token from vulnerable backend
    
    Yields:
        JWT token string
    """
    try:
        response = requests.post(
            f"{vulnerable_backend['url']}/api/auth/login-jwt-vulnerable",
            json={
                "username": admin_credentials["username"],
                "password": admin_credentials["password"]
            },
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                yield data.get("token")
                return
    except Exception as e:
        print(f"Error getting vulnerable JWT token: {e}")
    
    yield None

@pytest.fixture
def secure_jwt_token(secure_backend, admin_credentials):
    """
    Get a valid JWT token from secure backend
    
    Yields:
        JWT token string
    """
    try:
        response = requests.post(
            f"{secure_backend['url']}/api/auth/login-jwt-secure",
            json={
                "username": admin_credentials["username"],
                "password": admin_credentials["password"]
            },
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                yield data.get("token")
                return
    except Exception as e:
        print(f"Error getting secure JWT token: {e}")
    
    yield None

@pytest.fixture
def wordlist_path():
    """Get path to wordlist for brute-force testing"""
    return PROJECT_ROOT / "secrets" / "wordlist.txt"

@pytest.fixture
def data_output_dir():
    """Get data output directory"""
    data_dir = PROJECT_ROOT / "data"
    data_dir.mkdir(exist_ok=True, parents=True)
    return data_dir

@pytest.fixture
def figures_output_dir():
    """Get figures output directory"""
    fig_dir = PROJECT_ROOT / "report" / "figures"
    fig_dir.mkdir(exist_ok=True, parents=True)
    return fig_dir

@pytest.fixture
def keys_dir():
    """Get keys directory"""
    keys_dir = PROJECT_ROOT / "keys"
    keys_dir.mkdir(exist_ok=True, parents=True)
    return keys_dir

# Test data fixtures

@pytest.fixture
def sample_jwt_payload():
    """Sample JWT payload for testing"""
    return {
        "userId": "U001",
        "username": "admin",
        "role": "Admin",
        "iat": 1609459200,
        "exp": 1609462800
    }

@pytest.fixture
def sample_book_data():
    """Sample book data for testing"""
    return {
        "BookID": "B999",
        "Title": "Test Book",
        "ISBN": "123-456-7890",
        "GenreID": "G001",
        "AuthorID": "A001",
        "PublisherID": "P001",
        "YearPublished": 2024,
        "Pages": 300,
        "Price": 29.99
    }

@pytest.fixture
def timing_data_template():
    """Template for timing data CSV"""
    return "timestamp,request_id,backend,algorithm,response_time_ms,status_code,is_valid_token\n"

# Cleanup fixtures

@pytest.fixture(autouse=True)
def cleanup_test_files():
    """Cleanup test files after test"""
    yield
    # Add cleanup logic if needed
