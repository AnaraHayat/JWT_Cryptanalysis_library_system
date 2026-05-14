"""
Test Suite for ML Modules
Tests training data collection and model training
"""

import pytest
import json
import numpy as np
import tempfile
from pathlib import Path

from ml_model.collect_training_data import MLTrainingDataCollector
from ml_model.train_jwt_detector import JWTAnomalyModelTrainer
from core.utils import encode_jwt
import time


class TestTrainingDataCollection:
    """Test ML training data collection"""
    
    def test_generate_normal_tokens(self):
        """Test generating normal training tokens"""
        collector = MLTrainingDataCollector("vulnerable")
        
        normal_tokens = collector.generate_normal_tokens(count=20)
        
        assert len(normal_tokens) == 20
        assert all(t["label"] == "normal" for t in normal_tokens)
        assert all("token" in t for t in normal_tokens)
    
    def test_generate_normal_tokens_features(self):
        """Test that normal tokens have proper features"""
        collector = MLTrainingDataCollector("vulnerable")
        
        normal_tokens = collector.generate_normal_tokens(count=5)
        
        # Check first token features
        token_features = normal_tokens[0]
        
        assert "token_length" in token_features
        assert "algorithm" in token_features
        assert "payload_size" in token_features
        assert "claim_count" in token_features
    
    def test_generate_malicious_tokens(self):
        """Test generating malicious training tokens"""
        collector = MLTrainingDataCollector("vulnerable")
        
        malicious_tokens = collector.generate_malicious_tokens(count=20)
        
        assert len(malicious_tokens) == 20
        assert all(t["label"] == "malicious" for t in malicious_tokens)
        assert all("attack_type" in t for t in malicious_tokens)
    
    def test_malicious_tokens_have_attack_types(self):
        """Test that malicious tokens are labeled with attack types"""
        collector = MLTrainingDataCollector("vulnerable")
        
        malicious_tokens = collector.generate_malicious_tokens(count=50)
        
        attack_types = set(t.get("attack_type") for t in malicious_tokens)
        
        # Should have multiple attack types
        assert len(attack_types) > 1
        assert "algorithm_switching" in attack_types or "privilege_escalation" in attack_types
    
    def test_dataset_balance(self):
        """Test dataset balance"""
        collector = MLTrainingDataCollector("vulnerable")
        
        normal = collector.generate_normal_tokens(count=50)
        malicious = collector.generate_malicious_tokens(count=50)
        
        collector.training_samples = normal + malicious
        
        stats = collector.get_dataset_statistics()
        
        assert stats["normal_samples"] == 50
        assert stats["malicious_samples"] == 50
        assert stats["balance_ratio"] == 1.0
    
    def test_save_training_dataset(self):
        """Test saving training dataset"""
        with tempfile.TemporaryDirectory() as tmpdir:
            collector = MLTrainingDataCollector("vulnerable")
            
            collector.generate_normal_tokens(count=10)
            collector.generate_malicious_tokens(count=10)
            
            filepath = Path(tmpdir) / "training_data.json"
            saved_path = collector.save_training_dataset(str(filepath))
            
            assert Path(saved_path).exists()
            
            # Verify content
            with open(saved_path, 'r') as f:
                data = json.load(f)
            
            assert data["total_samples"] == 20
            assert len(data["samples"]) == 20
    
    def test_dataset_statistics(self):
        """Test getting dataset statistics"""
        collector = MLTrainingDataCollector("vulnerable")
        
        collector.generate_normal_tokens(count=30)
        collector.generate_malicious_tokens(count=20)
        
        stats = collector.get_dataset_statistics()
        
        assert stats["total_samples"] == 50
        assert stats["normal_samples"] == 30
        assert stats["malicious_samples"] == 20
        assert stats["balance_ratio"] == pytest.approx(20/30, rel=0.01)


class TestModelTraining:
    """Test ML model training"""
    
    def test_prepare_features(self):
        """Test feature preparation"""
        trainer = JWTAnomalyModelTrainer()
        
        # Create sample data
        training_data = [
            {
                "token_length": 200,
                "payload_size": 100,
                "claim_count": 5,
                "has_exp": True,
                "has_iat": True,
                "has_nbf": False,
                "has_jti": False,
                "has_role": True,
                "ttl_seconds": 3600,
                "label": "normal"
            },
            {
                "token_length": 150,
                "payload_size": 80,
                "claim_count": 3,
                "has_exp": False,
                "has_iat": True,
                "has_nbf": False,
                "has_jti": False,
                "has_role": False,
                "ttl_seconds": None,
                "label": "malicious"
            }
        ]
        
        X, y, features = trainer.prepare_features(training_data)
        
        assert X.shape[0] == 2  # 2 samples
        assert X.shape[1] == 9  # 9 features
        assert len(y) == 2
        assert len(features) == 9
    
    def test_train_isolation_forest(self):
        """Test training Isolation Forest model"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Generate training data
            collector = MLTrainingDataCollector("vulnerable")
            collector.generate_normal_tokens(count=50)
            collector.generate_malicious_tokens(count=50)
            
            # Prepare features
            trainer = JWTAnomalyModelTrainer(model_dir=tmpdir)
            X, y, features = trainer.prepare_features(collector.training_samples)
            
            # Train model
            metrics = trainer.train_isolation_forest(X, y, test_size=0.2)
            
            assert "train_accuracy" in metrics
            assert "test_accuracy" in metrics
            assert "precision" in metrics
            assert "recall" in metrics
            assert "f1" in metrics
            
            # Accuracy should be reasonable
            assert metrics["test_accuracy"] > 0.5
    
    def test_model_persistence(self):
        """Test saving and loading trained model"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Train model
            collector = MLTrainingDataCollector("vulnerable")
            collector.generate_normal_tokens(count=30)
            collector.generate_malicious_tokens(count=30)
            
            trainer = JWTAnomalyModelTrainer(model_dir=tmpdir)
            X, y, features = trainer.prepare_features(collector.training_samples)
            trainer.train_isolation_forest(X, y, test_size=0.2)
            
            # Save model
            model_path = trainer.save_model("test_model")
            assert Path(model_path).exists()
            
            # Load model
            trainer2 = JWTAnomalyModelTrainer(model_dir=tmpdir)
            loaded = trainer2.load_model("test_model")
            
            assert loaded is True
            assert trainer2.model is not None
    
    def test_model_prediction(self):
        """Test making predictions with trained model"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Train model
            collector = MLTrainingDataCollector("vulnerable")
            collector.generate_normal_tokens(count=40)
            collector.generate_malicious_tokens(count=40)
            
            trainer = JWTAnomalyModelTrainer(model_dir=tmpdir)
            X, y, features = trainer.prepare_features(collector.training_samples)
            trainer.train_isolation_forest(X, y, test_size=0.2)
            
            # Make prediction on single sample
            test_sample = X[0:1]
            prediction, confidence = trainer.predict(test_sample)
            
            assert prediction is not None
            assert 0 <= confidence <= 1
    
    def test_model_metadata(self):
        """Test model metadata"""
        with tempfile.TemporaryDirectory() as tmpdir:
            collector = MLTrainingDataCollector("vulnerable")
            collector.generate_normal_tokens(count=20)
            collector.generate_malicious_tokens(count=20)
            
            trainer = JWTAnomalyModelTrainer(model_dir=tmpdir)
            X, y, features = trainer.prepare_features(collector.training_samples)
            trainer.train_isolation_forest(X, y)
            
            report = trainer.get_model_report()
            
            assert report["trained"] is True
            assert report["model_type"] == "IsolationForest"
            assert "metadata" in report
            assert "features" in report
    
    def test_model_detects_anomalies(self):
        """Test that trained model detects anomalies"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Train model
            collector = MLTrainingDataCollector("vulnerable")
            collector.generate_normal_tokens(count=50)
            collector.generate_malicious_tokens(count=50)
            
            trainer = JWTAnomalyModelTrainer(model_dir=tmpdir)
            X, y, features = trainer.prepare_features(collector.training_samples)
            trainer.train_isolation_forest(X, y, test_size=0.2)
            
            # Get predictions for all samples
            predictions, _ = zip(*[trainer.predict(X[i:i+1]) for i in range(len(X))])
            
            # Should have mixed predictions
            assert len(set(predictions)) > 1


class TestModelAccuracy:
    """Test model accuracy metrics"""
    
    def test_model_accuracy_threshold(self):
        """Test that model achieves acceptable accuracy"""
        with tempfile.TemporaryDirectory() as tmpdir:
            collector = MLTrainingDataCollector("vulnerable")
            collector.generate_normal_tokens(count=50)
            collector.generate_malicious_tokens(count=50)
            
            trainer = JWTAnomalyModelTrainer(model_dir=tmpdir)
            X, y, features = trainer.prepare_features(collector.training_samples)
            metrics = trainer.train_isolation_forest(X, y, test_size=0.3)
            
            # Model should achieve >70% accuracy
            assert metrics["test_accuracy"] > 0.7
    
    def test_model_precision_recall_balance(self):
        """Test balance between precision and recall"""
        with tempfile.TemporaryDirectory() as tmpdir:
            collector = MLTrainingDataCollector("vulnerable")
            collector.generate_normal_tokens(count=50)
            collector.generate_malicious_tokens(count=50)
            
            trainer = JWTAnomalyModelTrainer(model_dir=tmpdir)
            X, y, features = trainer.prepare_features(collector.training_samples)
            metrics = trainer.train_isolation_forest(X, y, test_size=0.2)
            
            # Both precision and recall should be reasonable
            assert metrics["precision"] > 0.3
            assert metrics["recall"] > 0.3


class TestFeatureSelection:
    """Test feature selection for ML model"""
    
    def test_feature_diversity(self):
        """Test that selected features are diverse"""
        trainer = JWTAnomalyModelTrainer()
        
        sample_data = [
            {
                "token_length": 200,
                "payload_size": 100,
                "claim_count": 5,
                "has_exp": True,
                "has_iat": True,
                "has_nbf": False,
                "has_jti": False,
                "has_role": True,
                "ttl_seconds": 3600,
                "label": "normal"
            }
        ]
        
        X, y, features = trainer.prepare_features(sample_data)
        
        # Should have diverse features
        assert "token_length" in features
        assert "payload_size" in features
        assert "has_exp" in features
        assert "ttl_seconds" in features


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
