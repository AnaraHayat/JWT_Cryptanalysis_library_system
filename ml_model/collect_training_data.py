"""
ML Training Data Collection for JWT Anomaly Detection
Collects labeled dataset of normal and malicious JWT patterns
"""

import json
import logging
import random
import time
from typing import Dict, List, Tuple
from pathlib import Path
from datetime import datetime, timedelta

from core.jwt_config import DATA_PATHS, BACKENDS, API_ENDPOINTS, ML_CONFIG
from core.logging_setup import get_logger
from core.utils import encode_jwt, decode_jwt_without_verification, save_json_data
from core.jwt_anomaly_detector import JWTAnomalyDetector

logger = logging.getLogger(__name__)

class MLTrainingDataCollector:
    """Collects training data for ML-based JWT anomaly detection"""
    
    def __init__(self, backend_name: str = "vulnerable"):
        """Initialize training data collector"""
        self.backend = BACKENDS[backend_name]
        self.backend_name = backend_name
        self.detector = JWTAnomalyDetector()
        self.training_samples = []
    
    def generate_normal_tokens(self, count: int = 100, secret: str = "test-secret") -> List[Dict]:
        """
        Generate legitimate JWT tokens for training
        
        Args:
            count: Number of tokens to generate
            secret: Secret for HMAC signing
            
        Returns:
            List of token dictionaries with features
        """
        logger.info(f"Generating {count} normal JWT tokens...")
        
        normal_samples = []
        
        roles = ["user", "admin", "librarian", "member"]
        
        for i in range(count):
            # Generate realistic payload
            now = int(time.time())
            ttl = random.choice([3600, 7200, 86400])  # 1h, 2h, 24h
            
            payload = {
                "sub": f"user_{random.randint(1, 1000)}",
                "name": f"User {i}",
                "role": random.choice(roles),
                "iat": now,
                "exp": now + ttl,
                "iss": "jwt-library-system",
                "aud": "library-api"
            }
            
            try:
                token = encode_jwt(payload, secret, algorithm="HS256")
                
                # Extract features
                features = self.detector.extract_jwt_features(token)
                features["label"] = "normal"
                features["token"] = token  # Include token for reference
                
                normal_samples.append(features)
            except Exception as e:
                logger.error(f"Error generating normal token: {e}")
        
        self.training_samples.extend(normal_samples)
        logger.info(f"Generated {len(normal_samples)} normal samples")
        
        return normal_samples
    
    def generate_malicious_tokens(self, count: int = 100, secret: str = "test-secret") -> List[Dict]:
        """
        Generate malicious JWT tokens for training
        
        Args:
            count: Number of malicious tokens to generate
            secret: Secret for HMAC signing
            
        Returns:
            List of token dictionaries with features and anomalies
        """
        logger.info(f"Generating {count} malicious JWT tokens...")
        
        malicious_samples = []
        now = int(time.time())
        
        attack_types = [
            "algorithm_switching",
            "privilege_escalation",
            "claim_injection",
            "expired_token",
            "future_token",
            "missing_claims",
            "oversized_payload",
            "unknown_role"
        ]
        
        for i in range(count):
            attack_type = random.choice(attack_types)
            
            try:
                if attack_type == "algorithm_switching":
                    # Try to use HS256 when RS256 is expected
                    payload = {
                        "sub": f"user_{random.randint(1, 1000)}",
                        "role": "user",
                        "iat": now,
                        "exp": now + 3600
                    }
                    token = encode_jwt(payload, secret, algorithm="HS256")
                
                elif attack_type == "privilege_escalation":
                    # Non-admin claiming admin role
                    payload = {
                        "sub": f"user_{random.randint(1, 1000)}",
                        "role": "admin",  # Suspicious
                        "original_role": "user",  # Hint of escalation
                        "iat": now,
                        "exp": now + 3600
                    }
                    token = encode_jwt(payload, secret, algorithm="HS256")
                
                elif attack_type == "claim_injection":
                    # Inject additional claims
                    payload = {
                        "sub": f"user_{random.randint(1, 1000)}",
                        "role": "user",
                        "iat": now,
                        "exp": now + 3600,
                        "admin": True,  # Injected claim
                        "bypass_mfa": True,  # Injected claim
                    }
                    token = encode_jwt(payload, secret, algorithm="HS256")
                
                elif attack_type == "expired_token":
                    # Create expired token
                    payload = {
                        "sub": f"user_{random.randint(1, 1000)}",
                        "role": "user",
                        "iat": now - 7200,
                        "exp": now - 3600  # Already expired
                    }
                    token = encode_jwt(payload, secret, algorithm="HS256")
                
                elif attack_type == "future_token":
                    # Token issued in the future
                    payload = {
                        "sub": f"user_{random.randint(1, 1000)}",
                        "role": "user",
                        "iat": now + 86400,  # Issued 1 day from now
                        "exp": now + 90000
                    }
                    token = encode_jwt(payload, secret, algorithm="HS256")
                
                elif attack_type == "missing_claims":
                    # Missing critical claims
                    payload = {
                        "sub": f"user_{random.randint(1, 1000)}",
                        # Missing: role, iat, exp
                    }
                    token = encode_jwt(payload, secret, algorithm="HS256")
                
                elif attack_type == "oversized_payload":
                    # Inject large payload
                    payload = {
                        "sub": f"user_{random.randint(1, 1000)}",
                        "role": "user",
                        "iat": now,
                        "exp": now + 3600,
                        "large_data": "x" * 5000  # Large payload
                    }
                    token = encode_jwt(payload, secret, algorithm="HS256")
                
                elif attack_type == "unknown_role":
                    # Use unknown role value
                    payload = {
                        "sub": f"user_{random.randint(1, 1000)}",
                        "role": "superadmin",  # Unknown role
                        "iat": now,
                        "exp": now + 3600
                    }
                    token = encode_jwt(payload, secret, algorithm="HS256")
                
                else:
                    continue
                
                # Extract features
                features = self.detector.extract_jwt_features(token)
                features["label"] = "malicious"
                features["attack_type"] = attack_type
                features["token"] = token
                
                malicious_samples.append(features)
            
            except Exception as e:
                logger.error(f"Error generating {attack_type} token: {e}")
        
        self.training_samples.extend(malicious_samples)
        logger.info(f"Generated {len(malicious_samples)} malicious samples")
        
        return malicious_samples
    
    def collect_from_backend(self, num_legitimate: int = 50, num_attack_attempts: int = 50) -> List[Dict]:
        """
        Collect real training data from backend interactions
        
        Args:
            num_legitimate: Number of legitimate token interactions
            num_attack_attempts: Number of attack attempts to collect
            
        Returns:
            List of collected samples
        """
        logger.info(f"Collecting real training data from {self.backend_name} backend...")
        
        samples = []
        
        # Collect legitimate tokens
        logger.info(f"Collecting {num_legitimate} legitimate interactions...")
        from attacks.hijack_library_tokens import JWTAttacker
        attacker = JWTAttacker(self.backend_name)
        
        for i in range(num_legitimate):
            try:
                token = attacker.get_valid_token()
                if token:
                    features = self.detector.extract_jwt_features(token)
                    features["label"] = "normal"
                    features["source"] = "legitimate_login"
                    samples.append(features)
            except Exception as e:
                logger.debug(f"Error collecting legitimate token: {e}")
        
        # Collect attack attempts
        logger.info(f"Collecting {num_attack_attempts} attack attempts...")
        
        attack_strategies = [
            ("alg_none", attacker.create_alg_none_token()),
            ("weak_secret", attacker.brute_force_secret()),
        ]
        
        for attack_name, token in attack_strategies:
            if token:
                try:
                    features = self.detector.extract_jwt_features(token)
                    features["label"] = "malicious"
                    features["attack_type"] = attack_name
                    features["source"] = "attack_attempt"
                    samples.append(features)
                except Exception as e:
                    logger.debug(f"Error collecting {attack_name}: {e}")
        
        self.training_samples.extend(samples)
        logger.info(f"Collected {len(samples)} real training samples")
        
        return samples
    
    def save_training_dataset(self, filepath: str = None) -> str:
        """
        Save collected training data to disk
        
        Args:
            filepath: Output file path
            
        Returns:
            Path to saved dataset
        """
        if filepath is None:
            filepath = DATA_PATHS.get("ml_training_data", "data/ml_training_data.json")
        
        # Prepare dataset
        dataset = {
            "timestamp": datetime.now().isoformat(),
            "backend": self.backend_name,
            "total_samples": len(self.training_samples),
            "normal_samples": len([s for s in self.training_samples if s.get("label") == "normal"]),
            "malicious_samples": len([s for s in self.training_samples if s.get("label") == "malicious"]),
            "samples": self.training_samples
        }
        
        save_json_data(dataset, filepath)
        logger.info(f"Training dataset saved: {filepath}")
        
        return filepath
    
    def get_dataset_statistics(self) -> Dict[str, any]:
        """
        Get statistics about collected training data
        
        Returns:
            Dictionary with dataset statistics
        """
        normal = [s for s in self.training_samples if s.get("label") == "normal"]
        malicious = [s for s in self.training_samples if s.get("label") == "malicious"]
        
        if not normal and not malicious:
            return {"total_samples": 0}
        
        stats = {
            "total_samples": len(self.training_samples),
            "normal_samples": len(normal),
            "malicious_samples": len(malicious),
            "balance_ratio": len(malicious) / len(normal) if normal else 0,
            "feature_dimensions": len(self.training_samples[0]) if self.training_samples else 0,
        }
        
        # Feature statistics
        if normal:
            normal_lens = [s.get("token_length", 0) for s in normal]
            stats["normal_avg_token_length"] = sum(normal_lens) / len(normal_lens) if normal_lens else 0
        
        if malicious:
            mal_lens = [s.get("token_length", 0) for s in malicious]
            stats["malicious_avg_token_length"] = sum(mal_lens) / len(mal_lens) if mal_lens else 0
        
        return stats


def main():
    """Collect training data"""
    print("=" * 60)
    print("ML TRAINING DATA COLLECTION")
    print("=" * 60)
    
    collector = MLTrainingDataCollector("vulnerable")
    
    # Generate synthetic data
    print("\n[1/3] Generating synthetic training data...")
    normal = collector.generate_normal_tokens(count=100)
    print(f"  Generated {len(normal)} normal tokens")
    
    malicious = collector.generate_malicious_tokens(count=100)
    print(f"  Generated {len(malicious)} malicious tokens")
    
    # Get statistics
    print("\n[2/3] Dataset statistics:")
    stats = collector.get_dataset_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Save dataset
    print("\n[3/3] Saving training dataset...")
    filepath = collector.save_training_dataset()
    print(f"  Saved to: {filepath}")


if __name__ == "__main__":
    from core.logging_setup import initialize_all_loggers
    initialize_all_loggers()
    main()
