"""
Test Suite for Core Utilities (core/utils.py)
Tests JWT encoding/decoding, token forging, and entropy calculation
"""

import pytest
import json
import time
from core.utils import (
    encode_jwt, decode_jwt_without_verification, 
    calculate_entropy, save_json_data, save_csv_row
)
from core.jwt_config import DATA_PATHS
from pathlib import Path
import tempfile
import os


class TestJWTEncoding:
    """Test JWT encoding functionality"""
    
    def test_encode_jwt_hs256(self):
        """Test encoding JWT with HS256"""
        payload = {"sub": "user123", "role": "user"}
        secret = "test-secret"
        
        token = encode_jwt(payload, secret, algorithm="HS256")
        
        assert token is not None
        assert isinstance(token, str)
        assert token.count('.') == 2  # JWT has 3 parts
    
    def test_encode_jwt_with_timestamps(self):
        """Test encoding JWT with timestamp claims"""
        now = int(time.time())
        payload = {
            "sub": "user123",
            "iat": now,
            "exp": now + 3600
        }
        secret = "test-secret"
        
        token = encode_jwt(payload, secret, algorithm="HS256")
        
        assert token is not None
        assert isinstance(token, str)
    
    def test_encode_jwt_different_algorithms(self):
        """Test encoding with different algorithms"""
        payload = {"sub": "user123"}
        secret = "test-secret"
        
        for alg in ["HS256", "HS384", "HS512"]:
            token = encode_jwt(payload, secret, algorithm=alg)
            assert token is not None
            assert isinstance(token, str)


class TestJWTDecoding:
    """Test JWT decoding without verification"""
    
    def test_decode_valid_token(self):
        """Test decoding a valid JWT"""
        payload = {"sub": "user123", "role": "admin"}
        secret = "test-secret"
        
        token = encode_jwt(payload, secret, algorithm="HS256")
        decoded = decode_jwt_without_verification(token)
        
        assert decoded is not None
        assert "header" in decoded
        assert "payload" in decoded
        assert decoded["payload"]["sub"] == "user123"
        assert decoded["payload"]["role"] == "admin"
    
    def test_decode_extracts_header(self):
        """Test that header is correctly extracted"""
        payload = {"sub": "user123"}
        secret = "test-secret"
        
        token = encode_jwt(payload, secret, algorithm="HS256")
        decoded = decode_jwt_without_verification(token)
        
        assert decoded["header"]["alg"] == "HS256"
        assert decoded["header"]["typ"] == "JWT"
    
    def test_decode_malformed_token(self):
        """Test decoding malformed token"""
        malformed_token = "not.a.valid.token.structure"
        
        decoded = decode_jwt_without_verification(malformed_token)
        
        # Should return empty dict or handle gracefully
        assert isinstance(decoded, dict)
    
    def test_decode_alg_none_token(self):
        """Test decoding token with alg:none"""
        # Manually construct alg:none token
        import base64
        
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).decode().rstrip('=')
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "user"}).encode()).decode().rstrip('=')
        token = f"{header}.{payload}."
        
        decoded = decode_jwt_without_verification(token)
        
        assert decoded["header"]["alg"] == "none"
        assert decoded["payload"]["sub"] == "user"


class TestEntropyCalculation:
    """Test entropy calculation"""
    
    def test_calculate_entropy_uniform(self):
        """Test entropy of uniform distribution"""
        # All same character should have entropy = 0
        data = "aaaa"
        entropy = calculate_entropy(data)
        
        assert entropy == 0.0
    
    def test_calculate_entropy_random(self):
        """Test entropy of random string"""
        data = "abcdefghijklmnopqrstuvwxyz"
        entropy = calculate_entropy(data)
        
        assert entropy > 0
        assert entropy <= 26  # Max entropy for 26 characters
    
    def test_calculate_entropy_weak_secret(self):
        """Test entropy of weak secret"""
        weak_secret = "123456"
        entropy = calculate_entropy(weak_secret)
        
        # Should be lower entropy
        assert entropy < 10  # Rough threshold for weak
    
    def test_calculate_entropy_strong_secret(self):
        """Test entropy of strong secret"""
        strong_secret = "xK9$mL@2pQ#vJ8&nR%4wE1^sY6~uT3"
        entropy = calculate_entropy(strong_secret)
        
        # Should be higher entropy
        assert entropy > 4.0


class TestJSONDataHandling:
    """Test JSON data saving"""
    
    def test_save_json_data(self):
        """Test saving JSON data"""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test_data.json")
            data = {
                "test": "data",
                "number": 123,
                "list": [1, 2, 3]
            }
            
            save_json_data(data, filepath)
            
            assert os.path.exists(filepath)
            
            # Verify content
            with open(filepath, 'r') as f:
                loaded_data = json.load(f)
            
            assert loaded_data == data
    
    def test_save_json_creates_parent_dirs(self):
        """Test that parent directories are created"""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "nested", "dir", "test.json")
            data = {"test": "data"}
            
            save_json_data(data, filepath)
            
            assert os.path.exists(filepath)


class TestCSVHandling:
    """Test CSV data saving"""
    
    def test_save_csv_row(self):
        """Test saving CSV row"""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test_data.csv")
            
            headers = ["name", "value", "timestamp"]
            row_data = {"name": "test", "value": 42, "timestamp": "2024-01-01"}
            
            save_csv_row(filepath, row_data, headers=headers)
            
            assert os.path.exists(filepath)
            
            # Verify content
            with open(filepath, 'r') as f:
                content = f.read()
            
            assert "name" in content
            assert "test" in content
            assert "42" in content
    
    def test_save_csv_multiple_rows(self):
        """Test saving multiple CSV rows"""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test_data.csv")
            headers = ["id", "value"]
            
            # Save first row
            save_csv_row(filepath, {"id": 1, "value": "a"}, headers=headers)
            
            # Save second row
            save_csv_row(filepath, {"id": 2, "value": "b"}, headers=headers)
            
            # Verify both rows exist
            with open(filepath, 'r') as f:
                lines = f.readlines()
            
            assert len(lines) >= 3  # Header + 2 rows


class TestTokenForging:
    """Test token forging capabilities"""
    
    def test_forge_token_with_different_payload(self):
        """Test creating forged tokens with modified payloads"""
        # Original payload
        original_payload = {"sub": "user", "role": "user"}
        
        # Forged payload (privilege escalation)
        forged_payload = {"sub": "user", "role": "admin"}
        
        secret = "test-secret"
        
        original_token = encode_jwt(original_payload, secret)
        forged_token = encode_jwt(forged_payload, secret)
        
        # Tokens should be different
        assert original_token != forged_token
        
        # Decode and verify
        original_decoded = decode_jwt_without_verification(original_token)
        forged_decoded = decode_jwt_without_verification(forged_token)
        
        assert original_decoded["payload"]["role"] == "user"
        assert forged_decoded["payload"]["role"] == "admin"
    
    def test_forge_token_with_extended_expiry(self):
        """Test creating forged tokens with extended TTL"""
        now = int(time.time())
        
        normal_payload = {
            "sub": "user",
            "iat": now,
            "exp": now + 3600  # 1 hour
        }
        
        forged_payload = {
            "sub": "user",
            "iat": now,
            "exp": now + 86400 * 365  # 1 year!
        }
        
        secret = "test-secret"
        
        normal_token = encode_jwt(normal_payload, secret)
        forged_token = encode_jwt(forged_payload, secret)
        
        normal_decoded = decode_jwt_without_verification(normal_token)
        forged_decoded = decode_jwt_without_verification(forged_token)
        
        normal_ttl = normal_decoded["payload"]["exp"] - normal_decoded["payload"]["iat"]
        forged_ttl = forged_decoded["payload"]["exp"] - forged_decoded["payload"]["iat"]
        
        assert forged_ttl > normal_ttl


class TestErrorHandling:
    """Test error handling in utilities"""
    
    def test_decode_empty_token(self):
        """Test decoding empty token"""
        decoded = decode_jwt_without_verification("")
        assert isinstance(decoded, dict)
    
    def test_decode_none_token(self):
        """Test decoding None token"""
        decoded = decode_jwt_without_verification(None)
        assert isinstance(decoded, dict)
    
    def test_entropy_empty_string(self):
        """Test entropy of empty string"""
        entropy = calculate_entropy("")
        assert entropy == 0.0
    
    def test_entropy_single_char(self):
        """Test entropy of single character"""
        entropy = calculate_entropy("a")
        assert entropy == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
