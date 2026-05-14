"""
RSA Key Manager for JWT Secure Backend
Manages RSA key generation, storage, and rotation for RS256 JWT signing
"""

import os
import json
import logging
from pathlib import Path
from typing import Tuple, Optional, Dict
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from core.jwt_config import DATA_PATHS
from core.logging_setup import get_logger

logger = logging.getLogger(__name__)

class RSAKeyManager:
    """Manages RSA key generation, storage, and rotation for JWT operations"""
    
    def __init__(self, key_dir: str = "keys", key_name: str = "jwt_rsa"):
        """
        Initialize RSA key manager
        
        Args:
            key_dir: Directory to store keys
            key_name: Base name for key files
        """
        self.key_dir = Path(key_dir)
        self.key_name = key_name
        self.key_dir.mkdir(parents=True, exist_ok=True)
        
        self.private_key_path = self.key_dir / f"{key_name}_private.pem"
        self.public_key_path = self.key_dir / f"{key_name}_public.pem"
        self.key_metadata_path = self.key_dir / f"{key_name}_metadata.json"
    
    def generate_rsa_keypair(self, key_size: int = 2048, force_regenerate: bool = False) -> Tuple[str, str]:
        """
        Generate RSA keypair for JWT signing
        
        Args:
            key_size: RSA key size in bits (2048 or 4096 recommended)
            force_regenerate: Force regeneration even if keys exist
            
        Returns:
            Tuple of (private_key_pem, public_key_pem) as strings
        """
        # Check if keys already exist
        if (not force_regenerate and 
            self.private_key_path.exists() and 
            self.public_key_path.exists()):
            logger.info(f"RSA keypair already exists at {self.key_dir}")
            return self._load_keys()
        
        logger.info(f"Generating {key_size}-bit RSA keypair...")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Save keys
        self._save_keys(private_pem, public_pem, key_size)
        
        logger.info(f"RSA keypair generated and saved to {self.key_dir}")
        logger.info(f"  Private key: {self.private_key_path}")
        logger.info(f"  Public key: {self.public_key_path}")
        
        return private_pem, public_pem
    
    def _save_keys(self, private_pem: str, public_pem: str, key_size: int):
        """
        Save RSA keys to disk
        
        Args:
            private_pem: Private key in PEM format
            public_pem: Public key in PEM format
            key_size: Size of the key
        """
        # Save private key
        with open(self.private_key_path, 'w') as f:
            f.write(private_pem)
        os.chmod(self.private_key_path, 0o600)  # Restrict permissions
        
        # Save public key
        with open(self.public_key_path, 'w') as f:
            f.write(public_pem)
        
        # Save metadata
        metadata = {
            "generated_at": datetime.now().isoformat(),
            "key_size": key_size,
            "algorithm": "RSA",
            "key_version": 1,
            "status": "active"
        }
        
        with open(self.key_metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.debug(f"RSA keys saved with metadata")
    
    def _load_keys(self) -> Tuple[str, str]:
        """
        Load RSA keys from disk
        
        Returns:
            Tuple of (private_key_pem, public_key_pem) as strings
        """
        logger.debug(f"Loading RSA keys from {self.key_dir}")
        
        try:
            with open(self.private_key_path, 'r') as f:
                private_pem = f.read()
            
            with open(self.public_key_path, 'r') as f:
                public_pem = f.read()
            
            return private_pem, public_pem
        except FileNotFoundError as e:
            logger.error(f"RSA key file not found: {e}")
            raise
    
    def load_private_key(self) -> str:
        """
        Load private key for signing
        
        Returns:
            Private key in PEM format
        """
        if not self.private_key_path.exists():
            raise FileNotFoundError(f"Private key not found at {self.private_key_path}")
        
        with open(self.private_key_path, 'r') as f:
            return f.read()
    
    def load_public_key(self) -> str:
        """
        Load public key for verification
        
        Returns:
            Public key in PEM format
        """
        if not self.public_key_path.exists():
            raise FileNotFoundError(f"Public key not found at {self.public_key_path}")
        
        with open(self.public_key_path, 'r') as f:
            return f.read()
    
    def get_key_metadata(self) -> Dict[str, any]:
        """
        Get metadata about the current key
        
        Returns:
            Dictionary with key metadata
        """
        try:
            with open(self.key_metadata_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("Key metadata not found, keys may not be properly initialized")
            return {}
    
    def rotate_keys(self, new_key_size: int = 2048) -> Tuple[str, str]:
        """
        Rotate RSA keypair (archive old, generate new)
        
        Args:
            new_key_size: Size for new RSA key
            
        Returns:
            Tuple of (new_private_key_pem, new_public_key_pem)
        """
        logger.info("Starting RSA key rotation...")
        
        # Archive old keys if they exist
        if self.private_key_path.exists() and self.public_key_path.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive_private = self.key_dir / f"{self.key_name}_private_{timestamp}.pem.archived"
            archive_public = self.key_dir / f"{self.key_name}_public_{timestamp}.pem.archived"
            
            self.private_key_path.rename(archive_private)
            self.public_key_path.rename(archive_public)
            
            logger.info(f"Archived old keys:")
            logger.info(f"  {archive_private}")
            logger.info(f"  {archive_public}")
        
        # Generate new keys
        new_private, new_public = self.generate_rsa_keypair(new_key_size, force_regenerate=True)
        
        logger.info("Key rotation complete")
        return new_private, new_public
    
    def get_public_key_for_client(self) -> Dict[str, str]:
        """
        Get public key formatted for client consumption (e.g., via JWKS endpoint)
        
        Returns:
            Dictionary suitable for JSON serialization
        """
        public_key_pem = self.load_public_key()
        
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "jwt-2024-001",
                    "alg": "RS256",
                    "pem": public_key_pem,
                    "generated_at": self.get_key_metadata().get("generated_at", "unknown")
                }
            ]
        }
    
    def verify_key_integrity(self) -> bool:
        """
        Verify that RSA keys are valid and match
        
        Returns:
            True if keys are valid and match, False otherwise
        """
        try:
            private_pem = self.load_private_key()
            public_pem = self.load_public_key()
            
            # Load keys
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            
            private_key = serialization.load_pem_private_key(
                private_pem.encode(),
                password=None,
                backend=default_backend()
            )
            
            public_key = serialization.load_pem_public_key(
                public_pem.encode(),
                backend=default_backend()
            )
            
            # Verify public key matches
            derived_public = private_key.public_key()
            
            # Compare by serializing both
            derived_numbers = derived_public.public_numbers()
            stored_numbers = public_key.public_numbers()
            
            match = (derived_numbers.e == stored_numbers.e and 
                    derived_numbers.n == stored_numbers.n)
            
            if match:
                logger.info("RSA key integrity verified: keys match")
            else:
                logger.error("RSA key integrity check FAILED: keys do not match")
            
            return match
        
        except Exception as e:
            logger.error(f"RSA key integrity check error: {e}")
            return False
    
    def get_key_strength_report(self) -> Dict[str, any]:
        """
        Generate a report about the current key strength
        
        Returns:
            Dictionary with key strength information
        """
        metadata = self.get_key_metadata()
        key_size = metadata.get("key_size", 0)
        
        return {
            "key_size_bits": key_size,
            "key_strength": (
                "STRONG (4096 bits)" if key_size >= 4096 else
                "GOOD (2048 bits)" if key_size >= 2048 else
                "WEAK (<2048 bits)"
            ),
            "algorithm": metadata.get("algorithm", "RSA"),
            "generated_at": metadata.get("generated_at", "unknown"),
            "status": metadata.get("status", "unknown"),
            "recommendation": "Adequate for most applications" if key_size >= 2048 else "UPGRADE KEY SIZE"
        }


def initialize_rsa_keys(force_regenerate: bool = False) -> Tuple[str, str]:
    """
    Initialize or load RSA keys for the system
    
    Args:
        force_regenerate: Force regeneration of keys
        
    Returns:
        Tuple of (private_key_pem, public_key_pem)
    """
    key_manager = RSAKeyManager()
    
    if force_regenerate:
        logger.info("Force regenerating RSA keys...")
    
    private_key, public_key = key_manager.generate_rsa_keypair(force_regenerate=force_regenerate)
    
    return private_key, public_key


def main():
    """Test RSA key manager"""
    print("=" * 60)
    print("RSA KEY MANAGER TEST")
    print("=" * 60)
    
    # Initialize key manager
    key_manager = RSAKeyManager()
    
    # Generate keys
    print("\n[1/4] Generating RSA keypair...")
    private_key, public_key = key_manager.generate_rsa_keypair(key_size=2048)
    print(f"  Private key length: {len(private_key)} characters")
    print(f"  Public key length: {len(public_key)} characters")
    
    # Load keys
    print("\n[2/4] Loading keys...")
    loaded_private = key_manager.load_private_key()
    loaded_public = key_manager.load_public_key()
    print(f"  Keys loaded successfully")
    
    # Verify integrity
    print("\n[3/4] Verifying key integrity...")
    is_valid = key_manager.verify_key_integrity()
    print(f"  Integrity check: {'PASSED' if is_valid else 'FAILED'}")
    
    # Get metadata
    print("\n[4/4] Key information:")
    report = key_manager.get_key_strength_report()
    for key, value in report.items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    from core.logging_setup import initialize_all_loggers
    initialize_all_loggers()
    main()
