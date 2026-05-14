"""
Metrics Collection Framework
Collects quantified security metrics demonstrating vulnerability and mitigation effectiveness
"""

import json
import logging
import time
from typing import Dict, List, Tuple
from pathlib import Path
from datetime import datetime

from core.jwt_config import BACKENDS, API_ENDPOINTS, DATA_PATHS
from core.logging_setup import get_logger
from core.utils import save_json_data, save_csv_row, encode_jwt
from core.jwt_whitelist_middleware import JWTWhitelistMiddleware
from core.jwt_anomaly_detector import JWTAnomalyDetector

logger = logging.getLogger(__name__)

class MetricsCollector:
    """Collects comprehensive security metrics"""
    
    def __init__(self):
        """Initialize metrics collector"""
        self.metrics = {}
        self.whitelist = JWTWhitelistMiddleware()
        self.detector = JWTAnomalyDetector()
    
    def measure_attack_success_rate(self, backend_name: str, attack_attempts: int = 100) -> Dict[str, any]:
        """
        Measure success rate of JWT attacks on backend
        
        Args:
            backend_name: Backend to test ("vulnerable" or "secure")
            attack_attempts: Number of attack attempts
            
        Returns:
            Dictionary with success rate metrics
        """
        logger.info(f"Measuring attack success rate on {backend_name} backend ({attack_attempts} attempts)...")
        
        from attacks.hijack_library_tokens import JWTAttacker
        
        attacker = JWTAttacker(backend_name)
        
        # Test different attacks
        attack_results = {
            "alg_none": {"attempts": 0, "successes": 0},
            "brute_force": {"attempts": 0, "successes": 0},
            "forged_token": {"attempts": 0, "successes": 0},
        }
        
        # Test alg:none attack
        for i in range(attack_attempts // 3):
            attack_results["alg_none"]["attempts"] += 1
            try:
                token = attacker.create_alg_none_token()
                if token and attacker.test_token_access(token):
                    attack_results["alg_none"]["successes"] += 1
            except:
                pass
        
        # Test brute force
        for i in range(attack_attempts // 3):
            attack_results["brute_force"]["attempts"] += 1
            try:
                token = attacker.brute_force_secret()
                if token and attacker.test_token_access(token):
                    attack_results["brute_force"]["successes"] += 1
            except:
                pass
        
        # Test forged tokens
        for i in range(attack_attempts // 3):
            attack_results["forged_token"]["attempts"] += 1
            try:
                payload = {"sub": f"admin_{i}", "role": "admin"}
                token = encode_jwt(payload, "wrong_secret", algorithm="HS256")
                if token and attacker.test_token_access(token):
                    attack_results["forged_token"]["successes"] += 1
            except:
                pass
        
        # Calculate overall success rate
        total_attempts = sum(a["attempts"] for a in attack_results.values())
        total_successes = sum(a["successes"] for a in attack_results.values())
        success_rate = (total_successes / total_attempts * 100) if total_attempts > 0 else 0
        
        metrics = {
            "backend": backend_name,
            "timestamp": datetime.now().isoformat(),
            "total_attacks": total_attempts,
            "successful_attacks": total_successes,
            "attack_success_rate_percent": success_rate,
            "attack_breakdown": attack_results,
            "interpretation": (
                "HIGHLY VULNERABLE" if success_rate > 50 
                else "VULNERABLE" if success_rate > 10 
                else "PROTECTED" if success_rate < 1 
                else "STRONGLY PROTECTED"
            )
        }
        
        logger.info(f"Attack success rate: {success_rate:.1f}%")
        self.metrics[f"attack_success_{backend_name}"] = metrics
        
        return metrics
    
    def measure_detection_accuracy(self, num_samples: int = 100) -> Dict[str, any]:
        """
        Measure accuracy of anomaly detection
        
        Args:
            num_samples: Number of samples to test
            
        Returns:
            Dictionary with detection accuracy metrics
        """
        logger.info(f"Measuring anomaly detection accuracy ({num_samples} samples)...")
        
        from ml_model.collect_training_data import MLTrainingDataCollector
        
        collector = MLTrainingDataCollector("vulnerable")
        
        # Generate test samples
        normal_tokens = collector.generate_normal_tokens(count=num_samples // 2)
        malicious_tokens = collector.generate_malicious_tokens(count=num_samples // 2)
        
        # Test detection
        correct_normal = 0
        correct_malicious = 0
        false_positives = 0
        false_negatives = 0
        
        # Test normal tokens
        for token_data in normal_tokens:
            token = token_data.get("token")
            if token:
                analysis = self.detector.comprehensive_analysis(token, "RS256")
                if not analysis["is_suspicious"]:
                    correct_normal += 1
                else:
                    false_positives += 1
        
        # Test malicious tokens
        for token_data in malicious_tokens:
            token = token_data.get("token")
            if token:
                analysis = self.detector.comprehensive_analysis(token, "RS256")
                if analysis["is_suspicious"]:
                    correct_malicious += 1
                else:
                    false_negatives += 1
        
        # Calculate metrics
        total_correct = correct_normal + correct_malicious
        accuracy = (total_correct / num_samples * 100) if num_samples > 0 else 0
        precision = (correct_malicious / (correct_malicious + false_positives) * 100) if (correct_malicious + false_positives) > 0 else 0
        recall = (correct_malicious / (correct_malicious + false_negatives) * 100) if (correct_malicious + false_negatives) > 0 else 0
        
        metrics = {
            "timestamp": datetime.now().isoformat(),
            "test_samples": num_samples,
            "accuracy_percent": accuracy,
            "precision_percent": precision,
            "recall_percent": recall,
            "correct_normal": correct_normal,
            "correct_malicious": correct_malicious,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "interpretation": (
                "HIGHLY ACCURATE" if accuracy > 95
                else "ACCURATE" if accuracy > 90
                else "ACCEPTABLE" if accuracy > 80
                else "NEEDS IMPROVEMENT"
            )
        }
        
        logger.info(f"Detection accuracy: {accuracy:.1f}% (Precision: {precision:.1f}%, Recall: {recall:.1f}%)")
        self.metrics["detection_accuracy"] = metrics
        
        return metrics
    
    def measure_false_positive_rate(self, num_legitimate: int = 100) -> Dict[str, any]:
        """
        Measure false positive rate on legitimate tokens
        
        Args:
            num_legitimate: Number of legitimate tokens to test
            
        Returns:
            Dictionary with false positive metrics
        """
        logger.info(f"Measuring false positive rate ({num_legitimate} legitimate tokens)...")
        
        from ml_model.collect_training_data import MLTrainingDataCollector
        
        collector = MLTrainingDataCollector("vulnerable")
        tokens = collector.generate_normal_tokens(count=num_legitimate)
        
        false_positives = 0
        
        for token_data in tokens:
            token = token_data.get("token")
            if token:
                analysis = self.detector.comprehensive_analysis(token, "RS256")
                if analysis["is_suspicious"]:
                    false_positives += 1
        
        fpr = (false_positives / num_legitimate * 100) if num_legitimate > 0 else 0
        
        metrics = {
            "timestamp": datetime.now().isoformat(),
            "legitimate_tokens": num_legitimate,
            "false_positives": false_positives,
            "false_positive_rate_percent": fpr,
            "acceptable": fpr < 5,
            "interpretation": (
                "EXCELLENT" if fpr < 1
                else "GOOD" if fpr < 5
                else "ACCEPTABLE" if fpr < 10
                else "HIGH - NEEDS TUNING"
            )
        }
        
        logger.info(f"False positive rate: {fpr:.2f}%")
        self.metrics["false_positive_rate"] = metrics
        
        return metrics
    
    def measure_response_time_overhead(self, backend_name: str, num_requests: int = 100) -> Dict[str, any]:
        """
        Measure performance overhead of security checks
        
        Args:
            backend_name: Backend to test
            num_requests: Number of requests to measure
            
        Returns:
            Dictionary with performance metrics
        """
        logger.info(f"Measuring response time overhead on {backend_name} ({num_requests} requests)...")
        
        backend = BACKENDS.get(backend_name, {})
        endpoint = backend.get("url") + API_ENDPOINTS.get(backend_name, {}).get("books_protected", "/api/books")
        
        times = []
        
        for i in range(num_requests):
            try:
                start = time.perf_counter()
                import requests
                response = requests.get(endpoint, timeout=5)
                elapsed = (time.perf_counter() - start) * 1000  # Convert to ms
                times.append(elapsed)
            except Exception as e:
                logger.debug(f"Request error: {e}")
        
        if times:
            avg_time = sum(times) / len(times)
            min_time = min(times)
            max_time = max(times)
            
            metrics = {
                "backend": backend_name,
                "timestamp": datetime.now().isoformat(),
                "requests": len(times),
                "avg_response_time_ms": avg_time,
                "min_response_time_ms": min_time,
                "max_response_time_ms": max_time,
                "interpretation": (
                    "EXCELLENT" if avg_time < 100
                    else "GOOD" if avg_time < 200
                    else "ACCEPTABLE" if avg_time < 500
                    else "HIGH OVERHEAD"
                )
            }
            
            logger.info(f"Average response time: {avg_time:.2f}ms")
            self.metrics[f"response_time_{backend_name}"] = metrics
            
            return metrics
        
        return {}
    
    def measure_key_strength(self) -> Dict[str, any]:
        """Measure cryptographic key strength"""
        from core.rsa_key_manager import RSAKeyManager
        from analysis.jwt_entropy_analysis import EntropyAnalyzer
        
        logger.info("Measuring key strength...")
        
        key_manager = RSAKeyManager()
        report = key_manager.get_key_strength_report()
        
        # Also measure weak secret entropy
        weak_secret = "library-secret-123"
        weak_entropy = EntropyAnalyzer.estimate_secret_strength(weak_secret)
        
        metrics = {
            "timestamp": datetime.now().isoformat(),
            "rsa_key_strength": report,
            "weak_secret_analysis": {
                "secret": weak_secret[:5] + "***",
                "entropy_bits": weak_entropy["entropy_bits"],
                "crack_time": weak_entropy["crack_time_human"],
                "recommendation": weak_entropy["recommendation"]
            },
            "strength_improvement": {
                "rsa_bits": report.get("key_size_bits", 0),
                "weak_secret_bits": weak_entropy["entropy_bits"],
                "improvement_ratio": report.get("key_size_bits", 0) / weak_entropy["entropy_bits"]
            }
        }
        
        self.metrics["key_strength"] = metrics
        return metrics
    
    def generate_comprehensive_report(self) -> Dict[str, any]:
        """Generate comprehensive metrics report"""
        logger.info("Generating comprehensive metrics report...")
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "metrics_collection_date": datetime.now().isoformat(),
            "all_metrics": self.metrics,
            "summary": {
                "metrics_collected": len(self.metrics),
                "vulnerable_backend_success_rate": self.metrics.get("attack_success_vulnerable", {}).get("attack_success_rate_percent"),
                "secure_backend_success_rate": self.metrics.get("attack_success_secure", {}).get("attack_success_rate_percent"),
                "detection_accuracy": self.metrics.get("detection_accuracy", {}).get("accuracy_percent"),
                "false_positive_rate": self.metrics.get("false_positive_rate", {}).get("false_positive_rate_percent"),
            }
        }
        
        return report
    
    def save_metrics_report(self, filepath: str = None) -> str:
        """Save metrics report to disk"""
        if filepath is None:
            filepath = DATA_PATHS.get("metrics_report", "data/metrics_report.json")
        
        report = self.generate_comprehensive_report()
        save_json_data(report, filepath)
        
        logger.info(f"Metrics report saved: {filepath}")
        return filepath


def main():
    """Collect all metrics"""
    print("=" * 60)
    print("SECURITY METRICS COLLECTION")
    print("=" * 60)
    
    collector = MetricsCollector()
    
    # Measure attacks on vulnerable backend
    print("\n[1/5] Measuring attack success on vulnerable backend...")
    vulnerable_metrics = collector.measure_attack_success_rate("vulnerable", 30)
    print(f"  Success rate: {vulnerable_metrics['attack_success_rate_percent']:.1f}%")
    
    # Measure attacks on secure backend
    print("\n[2/5] Measuring attack success on secure backend...")
    secure_metrics = collector.measure_attack_success_rate("secure", 30)
    print(f"  Success rate: {secure_metrics['attack_success_rate_percent']:.1f}%")
    
    # Measure detection accuracy
    print("\n[3/5] Measuring anomaly detection accuracy...")
    detection_metrics = collector.measure_detection_accuracy(50)
    print(f"  Accuracy: {detection_metrics['accuracy_percent']:.1f}%")
    print(f"  Precision: {detection_metrics['precision_percent']:.1f}%")
    print(f"  Recall: {detection_metrics['recall_percent']:.1f}%")
    
    # Measure false positive rate
    print("\n[4/5] Measuring false positive rate...")
    fpr_metrics = collector.measure_false_positive_rate(50)
    print(f"  False positive rate: {fpr_metrics['false_positive_rate_percent']:.2f}%")
    
    # Measure key strength
    print("\n[5/5] Measuring key strength...")
    key_metrics = collector.measure_key_strength()
    print(f"  RSA key size: {key_metrics['rsa_key_strength']['key_size_bits']} bits")
    print(f"  Weak secret entropy: {key_metrics['weak_secret_analysis']['entropy_bits']:.1f} bits")
    print(f"  Improvement: {key_metrics['strength_improvement']['improvement_ratio']:.1f}x stronger")
    
    # Save report
    print("\nSaving comprehensive metrics report...")
    report_path = collector.save_metrics_report()
    print(f"  Report: {report_path}")


if __name__ == "__main__":
    from core.logging_setup import initialize_all_loggers
    initialize_all_loggers()
    main()
