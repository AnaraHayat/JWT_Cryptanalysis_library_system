"""
Validation Test Suite for Hardened Backend
Tests security improvements and verifies protections work correctly
"""

import json
import logging
import requests
from typing import Dict, List, Tuple
from pathlib import Path
from datetime import datetime, timedelta
import time

from core.jwt_config import BACKENDS, API_ENDPOINTS, DATA_PATHS
from core.logging_setup import get_logger
from core.utils import encode_jwt, save_json_data
from core.rsa_key_manager import RSAKeyManager
from core.jwt_whitelist_middleware import JWTWhitelistMiddleware
from core.jwt_anomaly_detector import JWTAnomalyDetector

logger = logging.getLogger(__name__)

class HardenedBackendValidator:
    """Validates that hardened backend protections work correctly"""
    
    def __init__(self):
        """Initialize validator"""
        self.secure_backend = BACKENDS.get("secure", {})
        self.test_results = []
        self.key_manager = RSAKeyManager()
        self.whitelist_middleware = JWTWhitelistMiddleware()
        self.anomaly_detector = JWTAnomalyDetector()
    
    def test_rsa_key_initialization(self) -> Dict[str, any]:
        """Test RSA key generation and initialization"""
        logger.info("Testing RSA key initialization...")
        
        result = {
            "test": "rsa_key_initialization",
            "timestamp": datetime.now().isoformat(),
            "passed": False,
            "details": {}
        }
        
        try:
            # Check if keys exist
            private_key = self.key_manager.load_private_key()
            public_key = self.key_manager.load_public_key()
            
            if not private_key or not public_key:
                raise Exception("Keys not found")
            
            # Verify key integrity
            is_valid = self.key_manager.verify_key_integrity()
            
            if is_valid:
                metadata = self.key_manager.get_key_metadata()
                result["passed"] = True
                result["details"] = {
                    "keys_exist": True,
                    "integrity_valid": True,
                    "key_size": metadata.get("key_size"),
                    "algorithm": metadata.get("algorithm")
                }
            
        except Exception as e:
            logger.error(f"RSA key test failed: {e}")
            result["details"]["error"] = str(e)
        
        self.test_results.append(result)
        return result
    
    def test_algorithm_validation(self) -> Dict[str, any]:
        """Test that only RS256 is accepted"""
        logger.info("Testing algorithm validation...")
        
        result = {
            "test": "algorithm_validation",
            "timestamp": datetime.now().isoformat(),
            "passed": False,
            "details": {
                "rs256_accepted": False,
                "hs256_rejected": False,
                "none_rejected": False
            }
        }
        
        try:
            # Test valid RS256 token
            payload = {
                "sub": "test_user",
                "role": "user",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600
            }
            
            private_key = self.key_manager.load_private_key()
            valid_token = encode_jwt(payload, private_key, algorithm="RS256")
            
            # Analyze with anomaly detector
            analysis = self.anomaly_detector.analyze_algorithm_anomaly(valid_token, "RS256")
            if analysis["risk_level"] == "low":
                result["details"]["rs256_accepted"] = True
            
            # Test invalid HS256 token
            weak_secret = "weak-secret"
            hs256_token = encode_jwt(payload, weak_secret, algorithm="HS256")
            
            analysis = self.anomaly_detector.analyze_algorithm_anomaly(hs256_token, "RS256")
            if analysis["risk_level"] in ["high", "critical"]:
                result["details"]["hs256_rejected"] = True
            
            # Test 'none' algorithm
            none_header = {"alg": "none", "typ": "JWT"}
            none_payload = payload
            # Construct manually since encode_jwt may not support 'none'
            
            if all(result["details"].values()):
                result["passed"] = True
        
        except Exception as e:
            logger.error(f"Algorithm validation test failed: {e}")
            result["details"]["error"] = str(e)
        
        self.test_results.append(result)
        return result
    
    def test_whitelist_enforcement(self) -> Dict[str, any]:
        """Test JWT whitelist enforcement"""
        logger.info("Testing whitelist enforcement...")
        
        result = {
            "test": "whitelist_enforcement",
            "timestamp": datetime.now().isoformat(),
            "passed": False,
            "details": {}
        }
        
        try:
            # Create test token
            test_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxNzMwMDAwMDAwfQ.sig"
            
            # Test 1: Token not in whitelist initially
            validation = self.whitelist_middleware.validate_token(test_token)
            test1_pass = not validation["valid"]
            result["details"]["token_rejected_when_not_whitelisted"] = test1_pass
            
            # Test 2: Register token
            registered = self.whitelist_middleware.register_new_token(test_token, "test_user")
            result["details"]["token_registered"] = registered
            
            # Test 3: Token accepted after registration
            validation = self.whitelist_middleware.validate_token(test_token)
            test3_pass = validation["valid"]
            result["details"]["token_accepted_when_whitelisted"] = test3_pass
            
            # Test 4: Logout and verify rejection
            self.whitelist_middleware.logout_token(test_token)
            validation = self.whitelist_middleware.validate_token(test_token)
            test4_pass = not validation["valid"]
            result["details"]["token_rejected_after_logout"] = test4_pass
            
            result["passed"] = all([test1_pass, test3_pass, test4_pass])
        
        except Exception as e:
            logger.error(f"Whitelist enforcement test failed: {e}")
            result["details"]["error"] = str(e)
        
        self.test_results.append(result)
        return result
    
    def test_anomaly_detection(self) -> Dict[str, any]:
        """Test anomaly detection on malicious patterns"""
        logger.info("Testing anomaly detection...")
        
        result = {
            "test": "anomaly_detection",
            "timestamp": datetime.now().isoformat(),
            "passed": False,
            "details": {
                "alg_switching_detected": False,
                "privilege_escalation_detected": False,
                "missing_claims_detected": False
            }
        }
        
        try:
            # Test 1: Algorithm switching (HS256 vs RS256)
            payload = {
                "sub": "user",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600
            }
            
            hs256_token = encode_jwt(payload, "secret", algorithm="HS256")
            analysis = self.anomaly_detector.comprehensive_analysis(hs256_token, "RS256")
            result["details"]["alg_switching_detected"] = analysis["is_suspicious"]
            
            # Test 2: Privilege escalation
            priv_payload = {
                "sub": "user",
                "role": "admin",
                "original_role": "user",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600
            }
            
            priv_token = encode_jwt(priv_payload, "secret", algorithm="HS256")
            analysis = self.anomaly_detector.comprehensive_analysis(priv_token, "RS256")
            result["details"]["privilege_escalation_detected"] = analysis["is_suspicious"]
            
            # Test 3: Missing claims
            minimal_payload = {"sub": "user"}
            minimal_token = encode_jwt(minimal_payload, "secret", algorithm="HS256")
            analysis = self.anomaly_detector.comprehensive_analysis(minimal_token, "RS256")
            result["details"]["missing_claims_detected"] = analysis["is_suspicious"]
            
            result["passed"] = all(result["details"].values())
        
        except Exception as e:
            logger.error(f"Anomaly detection test failed: {e}")
            result["details"]["error"] = str(e)
        
        self.test_results.append(result)
        return result
    
    def test_backend_connectivity(self) -> Dict[str, any]:
        """Test connectivity to hardened backend"""
        logger.info("Testing backend connectivity...")
        
        result = {
            "test": "backend_connectivity",
            "timestamp": datetime.now().isoformat(),
            "passed": False,
            "details": {}
        }
        
        try:
            backend_url = self.secure_backend.get("url")
            if not backend_url:
                raise Exception("No secure backend URL configured")
            
            # Try health check endpoint
            health_endpoint = backend_url + "/api/health"
            response = requests.get(health_endpoint, timeout=5)
            
            result["details"] = {
                "backend_url": backend_url,
                "status_code": response.status_code,
                "backend_responsive": response.status_code < 500
            }
            
            result["passed"] = result["details"]["backend_responsive"]
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Backend connectivity test failed: {e}")
            result["details"]["error"] = str(e)
        except Exception as e:
            logger.error(f"Backend connectivity test error: {e}")
            result["details"]["error"] = str(e)
        
        self.test_results.append(result)
        return result
    
    def test_protected_endpoint_security(self) -> Dict[str, any]:
        """Test that protected endpoints reject invalid tokens"""
        logger.info("Testing protected endpoint security...")
        
        result = {
            "test": "protected_endpoint_security",
            "timestamp": datetime.now().isoformat(),
            "passed": False,
            "details": {
                "no_token_rejected": False,
                "invalid_token_rejected": False,
                "malformed_token_rejected": False
            }
        }
        
        try:
            backend_url = self.secure_backend.get("url")
            if not backend_url:
                raise Exception("No secure backend URL configured")
            
            protected_endpoint = backend_url + API_ENDPOINTS.get("secure", {}).get("books_protected", "/api/books")
            
            # Test 1: No token
            response = requests.get(protected_endpoint, timeout=5)
            result["details"]["no_token_rejected"] = response.status_code in [401, 403]
            
            # Test 2: Invalid token format
            headers = {"Authorization": "Bearer invalid.token.format"}
            response = requests.get(protected_endpoint, headers=headers, timeout=5)
            result["details"]["invalid_token_rejected"] = response.status_code in [401, 403]
            
            # Test 3: Malformed token
            headers = {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiaGFjayJ9."}
            response = requests.get(protected_endpoint, headers=headers, timeout=5)
            result["details"]["malformed_token_rejected"] = response.status_code in [401, 403]
            
            result["passed"] = all(result["details"].values())
        
        except requests.exceptions.RequestException as e:
            logger.debug(f"Backend connectivity issue during security test: {e}")
            result["details"]["connectivity_error"] = True
        except Exception as e:
            logger.error(f"Protected endpoint security test error: {e}")
            result["details"]["error"] = str(e)
        
        self.test_results.append(result)
        return result
    
    def run_all_tests(self) -> Dict[str, any]:
        """Run all validation tests"""
        logger.info("Running all validation tests...")
        
        self.test_results = []
        
        tests = [
            self.test_rsa_key_initialization,
            self.test_algorithm_validation,
            self.test_whitelist_enforcement,
            self.test_anomaly_detection,
            self.test_backend_connectivity,
            self.test_protected_endpoint_security,
        ]
        
        for test_func in tests:
            try:
                test_func()
            except Exception as e:
                logger.error(f"Error running test {test_func.__name__}: {e}")
        
        # Summary
        passed = sum(1 for r in self.test_results if r.get("passed"))
        total = len(self.test_results)
        
        summary = {
            "timestamp": datetime.now().isoformat(),
            "total_tests": total,
            "passed_tests": passed,
            "failed_tests": total - passed,
            "pass_rate": (passed / total * 100) if total > 0 else 0,
            "all_passed": passed == total,
            "results": self.test_results
        }
        
        logger.info(f"Validation complete: {passed}/{total} tests passed ({summary['pass_rate']:.1f}%)")
        
        return summary
    
    def save_test_report(self, filepath: str = None) -> str:
        """Save test results to file"""
        if filepath is None:
            filepath = DATA_PATHS.get("validation_report", "data/validation_report.json")
        
        summary = {
            "timestamp": datetime.now().isoformat(),
            "total_tests": len(self.test_results),
            "passed_tests": sum(1 for r in self.test_results if r.get("passed")),
            "results": self.test_results
        }
        
        save_json_data(summary, filepath)
        logger.info(f"Test report saved: {filepath}")
        
        return filepath


def main():
    """Run validation tests"""
    print("=" * 60)
    print("HARDENED BACKEND VALIDATION TEST SUITE")
    print("=" * 60)
    
    validator = HardenedBackendValidator()
    
    # Run all tests
    print("\nRunning validation tests...")
    summary = validator.run_all_tests()
    
    # Print results
    print(f"\n{'=' * 60}")
    print(f"Test Results: {summary['passed_tests']}/{summary['total_tests']} passed")
    print(f"Pass Rate: {summary['pass_rate']:.1f}%")
    print(f"{'=' * 60}")
    
    for result in summary['results']:
        status = "PASS" if result.get("passed") else "FAIL"
        print(f"[{status}] {result['test']}")
    
    # Save report
    print(f"\nSaving report...")
    report_path = validator.save_test_report()
    print(f"Report saved: {report_path}")


if __name__ == "__main__":
    from core.logging_setup import initialize_all_loggers
    initialize_all_loggers()
    main()
