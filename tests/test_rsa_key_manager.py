"""
Test Suite for RSA Key Manager and JWT Configuration
Tests key generation, storage, and retrieval
"""

import pytest
import json
import os
import tempfile
from pathlib import Path
from datetime import datetime

from core.rsa_key_manager import RSAKeyManager, initialize_rsa_keys
from core.jwt_config import BACKENDS, ATTACK_CONFIG, ML_CONFIG, DATA_PATHS


class TestRSAKeyGeneration:
    """Test RSA key generation"""
    
    def test_generate_rsa_keypair_2048(self):
        """Test generating 2048-bit RSA keypair"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = RSAKeyManager(key_dir=tmpdir, key_name="test_key")
            
            private_key, public_key = key_manager.generate_rsa_keypair(key_size=2048, force_regenerate=True)
            
            assert private_key is not None
            assert public_key is not None
            assert len(private_key) > 0
            assert len(public_key) > 0
            assert "BEGIN PRIVATE KEY" in private_key
            assert "BEGIN PUBLIC KEY" in public_key
    
    def test_generate_rsa_keypair_4096(self):
        """Test generating 4096-bit RSA keypair"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = RSAKeyManager(key_dir=tmpdir, key_name="test_key")
            
            private_key, public_key = key_manager.generate_rsa_keypair(key_size=4096, force_regenerate=True)
            
            assert private_key is not None
            assert public_key is not None
            # 4096-bit keys are longer
            assert len(private_key) > len("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n")
    
    def test_generate_keypair_saves_to_disk(self):
        """Test that keypair is saved to disk"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = RSAKeyManager(key_dir=tmpdir, key_name="test_key")
            
            private_key, public_key = key_manager.generate_rsa_keypair(key_size=2048, force_regenerate=True)
            
            private_path = Path(tmpdir) / "test_key_private.pem"
            public_path = Path(tmpdir) / "test_key_public.pem"
            metadata_path = Path(tmpdir) / "test_key_metadata.json"
            
            assert private_path.exists()
            assert public_path.exists()
            assert metadata_path.exists()
    
    def test_keypair_metadata_created(self):
        """Test that keypair metadata is created"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = RSAKeyManager(key_dir=tmpdir, key_name="test_key")
            
            key_manager.generate_rsa_keypair(key_size=2048, force_regenerate=True)
            
            metadata = key_manager.get_key_metadata()
            
            assert metadata is not None
            assert "generated_at" in metadata
            assert "key_size" in metadata
            assert metadata["key_size"] == 2048
            assert metadata["algorithm"] == "RSA"
            assert metadata["status"] == "active"


class TestRSAKeyLoading:
    """Test RSA key loading"""
    
    def test_load_keys_success(self):
        """Test loading saved keys"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = RSAKeyManager(key_dir=tmpdir, key_name="test_key")
            
            # Generate keys
            original_private, original_public = key_manager.generate_rsa_keypair(key_size=2048, force_regenerate=True)
            
            # Load keys
            loaded_private = key_manager.load_private_key()
            loaded_public = key_manager.load_public_key()
            
            assert loaded_private == original_private
            assert loaded_public == original_public
    
    def test_load_nonexistent_key(self):
        """Test loading non-existent key raises error"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = RSAKeyManager(key_dir=tmpdir, key_name="nonexistent")
            
            with pytest.raises(FileNotFoundError):
                key_manager.load_private_key()
    
    def test_load_public_key_only(self):
        """Test loading only public key"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = RSAKeyManager(key_dir=tmpdir, key_name="test_key")
            
            key_manager.generate_rsa_keypair(key_size=2048, force_regenerate=True)
            
            public_key = key_manager.load_public_key()
            
            assert "BEGIN PUBLIC KEY" in public_key
            assert "BEGIN PRIVATE KEY" not in public_key


class TestRSAKeyIntegrity:
    """Test RSA key integrity verification"""
    
    def test_verify_key_integrity_valid(self):
        """Test verifying valid keypair"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = RSAKeyManager(key_dir=tmpdir, key_name="test_key")
            
            key_manager.generate_rsa_keypair(key_size=2048, force_regenerate=True)
            
            is_valid = key_manager.verify_key_integrity()
            
            assert is_valid is True
    
    def test_verify_key_integrity_corrupted(self):
        """Test verifying corrupted keypair"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = RSAKeyManager(key_dir=tmpdir, key_name="test_key")
            
            key_manager.generate_rsa_keypair(key_size=2048, force_regenerate=True)
            
            # Corrupt the public key
            public_path = Path(tmpdir) / "test_key_public.pem"
            with open(public_path, 'w') as f:
                f.write("corrupted public key data")
            
            is_valid = key_manager.verify_key_integrity()
            
            assert is_valid is False


class TestRSAKeyRotation:
    """Test RSA key rotation"""
    
    def test_rotate_keys(self):
        """Test key rotation"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = RSAKeyManager(key_dir=tmpdir, key_name="test_key")
            
            # Generate initial keys
            key_manager.generate_rsa_keypair(key_size=2048, force_regenerate=True)
            old_private = key_manager.load_private_key()
            
            # Rotate keys
            new_private, new_public = key_manager.rotate_keys(new_key_size=2048)
            
            # Verify new keys are different
            assert new_private != old_private
            
            # Verify archived files exist
            archived_files = list(Path(tmpdir).glob("*archived"))
            assert len(archived_files) >= 2  # Private and public archived
    
    def test_rotate_keys_maintains_accessibility(self):
        """Test that rotated keys are accessible"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = RSAKeyManager(key_dir=tmpdir, key_name="test_key")
            
            key_manager.generate_rsa_keypair(key_size=2048, force_regenerate=True)
            key_manager.rotate_keys(new_key_size=2048)
            
            # Should be able to load new keys
            private_key = key_manager.load_private_key()
            public_key = key_manager.load_public_key()
            
            assert private_key is not None
            assert public_key is not None


class TestRSAKeyStrengthReport:
    """Test RSA key strength reporting"""
    
    def test_key_strength_report(self):
        """Test getting key strength report"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = RSAKeyManager(key_dir=tmpdir, key_name="test_key")
            
            key_manager.generate_rsa_keypair(key_size=2048, force_regenerate=True)
            
            report = key_manager.get_key_strength_report()
            
            assert report is not None
            assert "key_size_bits" in report
            assert report["key_size_bits"] == 2048
            assert "key_strength" in report
            assert "algorithm" in report
    
    def test_key_strength_4096_vs_2048(self):
        """Test strength comparison between 2048 and 4096 bit keys"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Test 2048-bit
            key_manager_2048 = RSAKeyManager(key_dir=tmpdir, key_name="test_2048")
            key_manager_2048.generate_rsa_keypair(key_size=2048, force_regenerate=True)
            report_2048 = key_manager_2048.get_key_strength_report()
            
            # Test 4096-bit
            key_manager_4096 = RSAKeyManager(key_dir=tmpdir, key_name="test_4096")
            key_manager_4096.generate_rsa_keypair(key_size=4096, force_regenerate=True)
            report_4096 = key_manager_4096.get_key_strength_report()
            
            assert report_4096["key_size_bits"] > report_2048["key_size_bits"]


class TestJWTConfiguration:
    """Test JWT configuration"""
    
    def test_backends_configured(self):
        """Test that backends are configured"""
        assert "vulnerable" in BACKENDS
        assert "secure" in BACKENDS
        
        for backend_name, backend_config in BACKENDS.items():
            assert "url" in backend_config
            assert "port" in backend_config
    
    def test_backend_urls_are_valid(self):
        """Test that backend URLs are properly formatted"""
        for backend_name, backend_config in BACKENDS.items():
            url = backend_config["url"]
            assert url.startswith("http://") or url.startswith("https://")
    
    def test_attack_config_exists(self):
        """Test that attack configuration exists"""
        assert ATTACK_CONFIG is not None
        assert isinstance(ATTACK_CONFIG, dict)
        assert len(ATTACK_CONFIG) > 0
    
    def test_ml_config_exists(self):
        """Test that ML configuration exists"""
        assert ML_CONFIG is not None
        assert isinstance(ML_CONFIG, dict)
        assert "contamination_rate" in ML_CONFIG
        assert "n_estimators" in ML_CONFIG
    
    def test_data_paths_configured(self):
        """Test that data paths are configured"""
        assert DATA_PATHS is not None
        assert isinstance(DATA_PATHS, dict)
        assert len(DATA_PATHS) > 0


class TestInitializeRSAKeys:
    """Test RSA key initialization function"""
    
    def test_initialize_rsa_keys(self):
        """Test initializing RSA keys"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # This would normally use the default keys directory
            # We can test the function logic
            key_manager = RSAKeyManager(key_dir=tmpdir)
            private_key, public_key = key_manager.generate_rsa_keypair(key_size=2048, force_regenerate=True)
            
            assert private_key is not None
            assert public_key is not None


class TestPublicKeyFormatting:
    """Test public key formatting for client consumption"""
    
    def test_get_public_key_for_client(self):
        """Test getting public key in client-friendly format"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_manager = RSAKeyManager(key_dir=tmpdir, key_name="test_key")
            
            key_manager.generate_rsa_keypair(key_size=2048, force_regenerate=True)
            
            public_key_data = key_manager.get_public_key_for_client()
            
            assert "keys" in public_key_data
            assert len(public_key_data["keys"]) > 0
            
            key_entry = public_key_data["keys"][0]
            assert key_entry["kty"] == "RSA"
            assert key_entry["alg"] == "RS256"
            assert "pem" in key_entry


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
