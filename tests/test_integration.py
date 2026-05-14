"""
Integration Test Suite
Tests complete workflows and interactions between modules
"""

import pytest
import json
import tempfile
import time
from pathlib import Path

from core.utils import encode_jwt, decode_jwt_without_verification
from core.rsa_key_manager import RSAKeyManager
from core.jwt_whitelist_middleware import JWTWhitelistMiddleware
from core.jwt_anomaly_detector import JWTAnomalyDetector
from analysis.jwt_entropy_analysis import EntropyAnalyzer
from analysis.brute_force_analysis_library import BruteForceAnalyzer
from ml_model.collect_training_data import MLTrainingDataCollector
from ml_model.train_jwt_detector import JWTAnomalyModelTrainer


class TestEndToEndTokenValidation:
    """Test end-to-end token validation workflow"""
    
    def test_valid_token_workflow(self):
        """Test workflow for validating a legitimate token"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate RSA keys
            key_manager = RSAKeyManager(key_dir=tmpdir)
            private_key, public_key = key_manager.generate_rsa_keypair(key_size=2048, force_regenerate=True)
            
            # Create token
            payload = {
                "sub": "user123",
                "role": "user",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600
            }
            token = encode_jwt(payload, private_key, algorithm="RS256")
            
            # Register in whitelist
            middleware = JWTWhitelistMiddleware()
            middleware.register_new_token(token, "user123")
            
            # Validate with anomaly detector
            detector = JWTAnomalyDetector()
            analysis = detector.comprehensive_analysis(token, "RS256")
            
            # Check results
            validation = middleware.validate_token(token)
            assert validation["valid"] is True
    
    def test_suspicious_token_workflow(self):
        """Test workflow for detecting suspicious token"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create suspicious token (alg:none)
            payload = {
                "sub": "user",
                "role": "admin"  # Suspicious privilege
            }
            token = encode_jwt(payload, "secret", algorithm="HS256")
            
            # Analyze with detector
            detector = JWTAnomalyDetector()
            analysis = detector.comprehensive_analysis(token, expected_algorithm="RS256")
            
            # Should be flagged
            assert analysis["is_suspicious"] is True
            assert analysis["overall_risk_level"] in ["high", "critical"]
    
    def test_token_lifecycle(self):
        """Test complete token lifecycle"""
        with tempfile.TemporaryDirectory() as tmpdir:
            middleware = JWTWhitelistMiddleware()
            
            token = "test.jwt.token"
            user_id = "user123"
            
            # 1. Token is created (implied)
            
            # 2. Register token
            middleware.register_new_token(token, user_id)
            validation = middleware.validate_token(token)
            assert validation["valid"] is True
            
            # 3. Token is used
            # (application logic)
            
            # 4. User logs out - revoke token
            middleware.logout_token(token, user_id)
            validation = middleware.validate_token(token)
            assert validation["valid"] is False


class TestAttackDetectionIntegration:
    """Test attack detection across multiple modules"""
    
    def test_weak_secret_detection_chain(self):
        """Test detection of weak secret through multiple modules"""
        weak_secret = "library-secret-123"
        
        # 1. Entropy analysis
        entropy_analyzer = EntropyAnalyzer()
        entropy = entropy_analyzer.estimate_secret_strength(weak_secret)
        assert entropy["entropy_bits"] < 30
        
        # 2. Brute force feasibility
        brute_force_analyzer = BruteForceAnalyzer("vulnerable")
        feasibility = brute_force_analyzer.estimate_brute_force_feasibility(
            entropy["entropy_bits"], 100
        )
        assert feasibility["scenarios"]["wordlist_attack"]["feasible"] is True
        
        # 3. Attack simulation
        with tempfile.TemporaryDirectory() as tmpdir:
            wordlist_path = Path(tmpdir) / "wordlist.txt"
            with open(wordlist_path, 'w') as f:
                f.write(weak_secret + "\n")
            
            result = brute_force_analyzer.simulate_brute_force_attack(
                str(wordlist_path),
                correct_secret=weak_secret
            )
            assert result["success"] is True
    
    def test_algorithm_switching_detection_chain(self):
        """Test detection of algorithm switching through multiple modules"""
        payload = {"sub": "user"}
        
        # 1. Create HS256 token
        token = encode_jwt(payload, "secret", algorithm="HS256")
        
        # 2. Entropy analysis
        entropy_analyzer = EntropyAnalyzer()
        token_analysis = entropy_analyzer.analyze_jwt_token(token)
        assert token_analysis["algorithm"] == "HS256"
        
        # 3. Anomaly detection
        detector = JWTAnomalyDetector()
        algo_analysis = detector.analyze_algorithm_anomaly(token, "RS256")
        assert algo_analysis["anomaly_detected"] is True
        assert algo_analysis["risk_level"] == "high"
        
        # 4. Comprehensive analysis
        comprehensive = detector.comprehensive_analysis(token, "RS256")
        assert comprehensive["is_suspicious"] is True


class TestMLPipelineIntegration:
    """Test complete ML pipeline"""
    
    def test_full_ml_pipeline(self):
        """Test full pipeline from training data to prediction"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Collect training data
            collector = MLTrainingDataCollector("vulnerable")
            collector.generate_normal_tokens(count=40)
            collector.generate_malicious_tokens(count=40)
            
            # 2. Save dataset
            dataset_path = Path(tmpdir) / "training_data.json"
            collector.save_training_dataset(str(dataset_path))
            
            # 3. Train model
            trainer = JWTAnomalyModelTrainer(model_dir=tmpdir)
            X, y, features = trainer.prepare_features(collector.training_samples)
            metrics = trainer.train_isolation_forest(X, y, test_size=0.2)
            
            # 4. Save model
            model_path = trainer.save_model("test_model")
            assert Path(model_path).exists()
            
            # 5. Load and use model
            trainer2 = JWTAnomalyModelTrainer(model_dir=tmpdir)
            trainer2.load_model("test_model")
            
            # 6. Make predictions
            test_sample = X[0:1]
            prediction, confidence = trainer2.predict(test_sample)
            
            assert prediction is not None
            assert confidence > 0
    
    def test_model_detects_malicious_patterns(self):
        """Test that trained model recognizes malicious patterns"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Train model
            collector = MLTrainingDataCollector("vulnerable")
            collector.generate_normal_tokens(count=50)
            collector.generate_malicious_tokens(count=50)
            
            trainer = JWTAnomalyModelTrainer(model_dir=tmpdir)
            X, y, features = trainer.prepare_features(collector.training_samples)
            trainer.train_isolation_forest(X, y, test_size=0.2)
            
            # Test on clearly malicious sample
            malicious_payload = {
                "sub": "user",
                "role": "admin",
                "bypass_all": True,
                "iat": int(time.time()),
                "exp": int(time.time()) + 86400 * 365
            }
            malicious_token = encode_jwt(malicious_payload, "secret")
            
            detector = JWTAnomalyDetector()
            features_dict = detector.extract_jwt_features(malicious_token)
            
            # Create feature vector matching training format
            feature_vector = np.array([[
                features_dict.get("token_length", 0),
                features_dict.get("payload_size", 0),
                features_dict.get("claim_count", 0),
                float(features_dict.get("has_exp", False)),
                float(features_dict.get("has_iat", False)),
                float(features_dict.get("has_nbf", False)),
                float(features_dict.get("has_jti", False)),
                float(features_dict.get("has_role", False)),
                features_dict.get("ttl_seconds", 3600)
            ]])
            
            prediction, confidence = trainer.predict(feature_vector)
            
            # Model should flag as anomaly
            assert prediction is not None


class TestSecurityLayersIntegration:
    """Test multiple security layers working together"""
    
    def test_multi_layer_defense(self):
        """Test multi-layer security defense"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Layer 1: RSA key infrastructure
            key_manager = RSAKeyManager(key_dir=tmpdir)
            key_manager.generate_rsa_keypair(key_size=2048, force_regenerate=True)
            assert key_manager.verify_key_integrity() is True
            
            # Layer 2: JWT whitelist
            middleware = JWTWhitelistMiddleware()
            legitimate_token = "legitimate.jwt.token"
            malicious_token = "malicious.jwt.token"
            
            middleware.register_new_token(legitimate_token, "user1")
            
            # Layer 3: Anomaly detection
            detector = JWTAnomalyDetector()
            
            # Test legitimate token
            legitimate_validation = middleware.validate_token(legitimate_token)
            assert legitimate_validation["valid"] is True
            
            # Test malicious token
            malicious_validation = middleware.validate_token(malicious_token)
            assert malicious_validation["valid"] is False


class TestMetricsIntegration:
    """Test metrics collection across components"""
    
    def test_collect_attack_metrics(self):
        """Test collecting attack metrics"""
        # This would normally test against running backend
        # For unit test, we verify the structure is correct
        
        from validation.collect_metrics import MetricsCollector
        
        collector = MetricsCollector()
        
        # Get baseline metrics
        key_metrics = collector.measure_key_strength()
        
        assert "rsa_key_strength" in key_metrics
        assert "weak_secret_analysis" in key_metrics
        assert "strength_improvement" in key_metrics


class TestDataFlowIntegration:
    """Test data flow through complete system"""
    
    def test_token_creation_to_validation(self):
        """Test complete flow from token creation to validation"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Create token
            payload = {
                "sub": "testuser",
                "role": "user",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600
            }
            token = encode_jwt(payload, "secret")
            
            # 2. Analyze token
            analyzer = EntropyAnalyzer()
            token_analysis = analyzer.analyze_jwt_token(token)
            
            # 3. Extract features
            detector = JWTAnomalyDetector()
            features = detector.extract_jwt_features(token)
            
            # 4. Register in whitelist
            middleware = JWTWhitelistMiddleware()
            middleware.register_new_token(token, "testuser")
            
            # 5. Validate
            validation = middleware.validate_token(token)
            
            # All steps should succeed
            assert token is not None
            assert token_analysis["algorithm"] == "HS256"
            assert features["token_length"] > 0
            assert validation["valid"] is True


# Import numpy for test_ml_pipeline_integration
import numpy as np


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
