"""
ML Model Training for JWT Anomaly Detection
Trains Isolation Forest model on JWT behavioral features
"""

import json
import logging
import pickle
from typing import Dict, List, Tuple, Any
from pathlib import Path
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score, 
    precision_score, recall_score, f1_score, accuracy_score
)

from core.jwt_config import DATA_PATHS, ML_CONFIG
from core.logging_setup import get_logger
from core.utils import save_json_data

logger = logging.getLogger(__name__)

class JWTAnomalyModelTrainer:
    """Trains ML models for JWT anomaly detection"""
    
    def __init__(self, model_dir: str = "ml_model"):
        """Initialize model trainer"""
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = []
        self.model_metadata = {}
    
    def prepare_features(self, training_data: List[Dict]) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Prepare feature matrix and labels from training data
        
        Args:
            training_data: List of JWT feature dictionaries
            
        Returns:
            Tuple of (feature_matrix, labels, feature_names)
        """
        logger.info(f"Preparing features from {len(training_data)} samples...")
        
        # Select features for ML model
        feature_names = [
            "token_length",
            "payload_size",
            "claim_count",
            "has_exp",
            "has_iat",
            "has_nbf",
            "has_jti",
            "has_role",
            "ttl_seconds"
        ]
        
        # Handle missing TTL
        for sample in training_data:
            if "ttl_seconds" not in sample or sample["ttl_seconds"] is None:
                sample["ttl_seconds"] = 3600  # Default to 1 hour
        
        # Ensure all features exist
        for sample in training_data:
            for feat in feature_names:
                if feat not in sample:
                    sample[feat] = 0
        
        # Create feature matrix
        X = []
        y = []
        
        for sample in training_data:
            try:
                row = [
                    sample.get("token_length", 0),
                    sample.get("payload_size", 0),
                    sample.get("claim_count", 0),
                    float(sample.get("has_exp", False)),
                    float(sample.get("has_iat", False)),
                    float(sample.get("has_nbf", False)),
                    float(sample.get("has_jti", False)),
                    float(sample.get("has_role", False)),
                    sample.get("ttl_seconds", 3600)
                ]
                X.append(row)
                
                # Label: normal=1, malicious=-1 (for Isolation Forest)
                label = 1 if sample.get("label") == "normal" else -1
                y.append(label)
            except Exception as e:
                logger.warning(f"Error processing sample: {e}")
        
        X = np.array(X, dtype=float)
        y = np.array(y, dtype=int)
        
        logger.info(f"Prepared {len(X)} feature vectors with {len(feature_names)} features")
        logger.info(f"  Normal samples: {sum(1 for label in y if label == 1)}")
        logger.info(f"  Malicious samples: {sum(1 for label in y if label == -1)}")
        
        self.feature_names = feature_names
        return X, y, feature_names
    
    def train_isolation_forest(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2) -> Dict[str, any]:
        """
        Train Isolation Forest model
        
        Args:
            X: Feature matrix
            y: Labels (1 for normal, -1 for malicious)
            test_size: Fraction of data for testing
            
        Returns:
            Dictionary with training metrics
        """
        logger.info("Training Isolation Forest model...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        self.model = IsolationForest(
            contamination=ML_CONFIG.get("contamination_rate", 0.1),
            random_state=42,
            n_estimators=ML_CONFIG.get("n_estimators", 100)
        )
        
        self.model.fit(X_train_scaled)
        
        # Make predictions
        y_pred_train = self.model.predict(X_train_scaled)
        y_pred_test = self.model.predict(X_test_scaled)
        
        # Calculate metrics
        # Isolation Forest returns: 1 for inliers, -1 for outliers
        # Convert to: 1 for normal, -1 for malicious
        y_pred_test_binary = y_pred_test.copy()
        y_test_binary = y_test.copy()
        
        # Convert predictions to labels for metrics
        metrics = {
            "train_accuracy": accuracy_score(y_train, y_pred_train),
            "test_accuracy": accuracy_score(y_test, y_pred_test),
            "precision": precision_score(y_test, y_pred_test, pos_label=-1, zero_division=0),
            "recall": recall_score(y_test, y_pred_test, pos_label=-1, zero_division=0),
            "f1": f1_score(y_test, y_pred_test, pos_label=-1, zero_division=0),
        }
        
        # Generate classification report
        class_report = classification_report(
            y_test, y_pred_test, 
            target_names=["malicious", "normal"],
            output_dict=True,
            zero_division=0
        )
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred_test)
        
        logger.info(f"Model training complete:")
        logger.info(f"  Train accuracy: {metrics['train_accuracy']:.4f}")
        logger.info(f"  Test accuracy: {metrics['test_accuracy']:.4f}")
        logger.info(f"  Precision: {metrics['precision']:.4f}")
        logger.info(f"  Recall: {metrics['recall']:.4f}")
        logger.info(f"  F1-Score: {metrics['f1']:.4f}")
        
        self.model_metadata = {
            "model_type": "IsolationForest",
            "trained_at": datetime.now().isoformat(),
            "contamination_rate": ML_CONFIG.get("contamination_rate", 0.1),
            "n_estimators": ML_CONFIG.get("n_estimators", 100),
            "feature_names": self.feature_names,
            "test_size": test_size,
            "metrics": metrics,
            "classification_report": class_report,
            "confusion_matrix": cm.tolist()
        }
        
        return metrics
    
    def save_model(self, model_name: str = "jwt_anomaly_detector") -> str:
        """
        Save trained model to disk
        
        Args:
            model_name: Base name for model files
            
        Returns:
            Path to saved model
        """
        if self.model is None:
            logger.error("No model trained yet")
            return ""
        
        logger.info(f"Saving model: {model_name}...")
        
        # Save model
        model_path = self.model_dir / f"{model_name}.pkl"
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        logger.info(f"  Model saved: {model_path}")
        
        # Save scaler
        scaler_path = self.model_dir / f"{model_name}_scaler.pkl"
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        logger.info(f"  Scaler saved: {scaler_path}")
        
        # Save metadata
        metadata_path = self.model_dir / f"{model_name}_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(self.model_metadata, f, indent=2)
        logger.info(f"  Metadata saved: {metadata_path}")
        
        return str(model_path)
    
    def load_model(self, model_name: str = "jwt_anomaly_detector") -> bool:
        """
        Load trained model from disk
        
        Args:
            model_name: Base name for model files
            
        Returns:
            True if loaded successfully
        """
        try:
            model_path = self.model_dir / f"{model_name}.pkl"
            scaler_path = self.model_dir / f"{model_name}_scaler.pkl"
            metadata_path = self.model_dir / f"{model_name}_metadata.json"
            
            if not model_path.exists():
                logger.error(f"Model not found: {model_path}")
                return False
            
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            
            with open(metadata_path, 'r') as f:
                self.model_metadata = json.load(f)
            
            self.feature_names = self.model_metadata.get("feature_names", [])
            
            logger.info(f"Model loaded: {model_path}")
            return True
        
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False
    
    def predict(self, features: np.ndarray) -> Tuple[int, float]:
        """
        Predict using trained model
        
        Args:
            features: Feature vector or matrix
            
        Returns:
            Tuple of (prediction, confidence)
        """
        if self.model is None:
            logger.error("No model loaded")
            return None, 0.0
        
        try:
            # Scale features
            features_scaled = self.scaler.transform(features.reshape(1, -1) if features.ndim == 1 else features)
            
            # Predict
            prediction = self.model.predict(features_scaled)
            
            # Get anomaly score
            anomaly_score = self.model.score_samples(features_scaled)
            
            # Convert score to confidence (0-1)
            confidence = 1 / (1 + np.exp(anomaly_score))  # Sigmoid
            
            return prediction[0], float(confidence[0])
        
        except Exception as e:
            logger.error(f"Error during prediction: {e}")
            return None, 0.0
    
    def get_model_report(self) -> Dict[str, any]:
        """
        Get comprehensive model report
        
        Returns:
            Dictionary with model information
        """
        return {
            "model_type": "IsolationForest",
            "trained": self.model is not None,
            "metadata": self.model_metadata,
            "feature_count": len(self.feature_names),
            "features": self.feature_names
        }


def main():
    """Train JWT anomaly detection model"""
    from ml_model.collect_training_data import MLTrainingDataCollector
    
    print("=" * 60)
    print("ML MODEL TRAINING - JWT ANOMALY DETECTION")
    print("=" * 60)
    
    # Collect training data
    print("\n[1/4] Collecting training data...")
    collector = MLTrainingDataCollector("vulnerable")
    
    normal = collector.generate_normal_tokens(count=100)
    malicious = collector.generate_malicious_tokens(count=100)
    stats = collector.get_dataset_statistics()
    print(f"  Dataset: {stats['normal_samples']} normal, {stats['malicious_samples']} malicious")
    
    # Save dataset
    print("\n[2/4] Saving training dataset...")
    dataset_path = collector.save_training_dataset()
    print(f"  Saved: {dataset_path}")
    
    # Train model
    print("\n[3/4] Training Isolation Forest model...")
    trainer = JWTAnomalyModelTrainer()
    
    X, y, features = trainer.prepare_features(collector.training_samples)
    metrics = trainer.train_isolation_forest(X, y, test_size=0.2)
    
    print(f"  Accuracy: {metrics['test_accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall: {metrics['recall']:.4f}")
    print(f"  F1-Score: {metrics['f1']:.4f}")
    
    # Save model
    print("\n[4/4] Saving trained model...")
    model_path = trainer.save_model("jwt_anomaly_detector")
    print(f"  Saved: {model_path}")
    
    # Get report
    print("\nModel Report:")
    report = trainer.get_model_report()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    from core.logging_setup import initialize_all_loggers
    initialize_all_loggers()
    main()
