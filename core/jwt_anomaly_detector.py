"""
JWT Anomaly Detection Module
Uses behavioral analysis and ML to detect suspicious JWT patterns
"""

import json
import logging
from typing import Dict, List, Tuple, Any
from pathlib import Path
from datetime import datetime
import statistics

from core.jwt_config import DATA_PATHS, ML_CONFIG
from core.logging_setup import get_logger
from core.utils import decode_jwt_without_verification

logger = logging.getLogger(__name__)

class JWTAnomalyDetector:
    """Detects anomalous JWT patterns and behaviors"""
    
    def __init__(self):
        """Initialize anomaly detector"""
        self.normal_patterns = {}
        self.anomaly_log = []
    
    def extract_jwt_features(self, token: str) -> Dict[str, any]:
        """
        Extract behavioral features from JWT token
        
        Args:
            token: JWT token to analyze
            
        Returns:
            Dictionary with extracted features
        """
        try:
            decoded = decode_jwt_without_verification(token)
            header = decoded.get("header", {})
            payload = decoded.get("payload", {})
            
            # Basic features
            features = {
                "token_length": len(token),
                "algorithm": header.get("alg", "unknown"),
                "has_kid": "kid" in header,
                "has_typ": "typ" in header,
                "token_type": header.get("typ", "unknown"),
                
                # Payload features
                "payload_size": len(json.dumps(payload)),
                "claim_count": len(payload),
                "has_exp": "exp" in payload,
                "has_iat": "iat" in payload,
                "has_nbf": "nbf" in payload,
                "has_jti": "jti" in payload,
                "has_sub": "sub" in payload,
                "has_aud": "aud" in payload,
                "has_iss": "iss" in payload,
                "has_role": "role" in payload or "roles" in payload,
                "has_permissions": "permissions" in payload,
                
                # Security claims
                "role_value": payload.get("role") or payload.get("roles"),
                "user_id": payload.get("sub") or payload.get("user_id"),
                
                # Timestamp analysis
                "issued_at": payload.get("iat"),
                "expires_at": payload.get("exp"),
            }
            
            # Calculate TTL if possible
            if features["issued_at"] and features["expires_at"]:
                ttl = features["expires_at"] - features["issued_at"]
                features["ttl_seconds"] = ttl
            
            return features
        
        except Exception as e:
            logger.error(f"Error extracting JWT features: {e}")
            return {}
    
    def analyze_algorithm_anomaly(self, token: str, expected_algorithm: str = "RS256") -> Dict[str, any]:
        """
        Detect algorithm-based anomalies
        
        Args:
            token: JWT token to analyze
            expected_algorithm: Expected signing algorithm
            
        Returns:
            Dictionary with anomaly analysis
        """
        decoded = decode_jwt_without_verification(token)
        algorithm = decoded.get("header", {}).get("alg", "unknown")
        
        anomalies = []
        risk_level = "low"
        
        # Check for algorithm mismatch
        if algorithm != expected_algorithm:
            anomalies.append(f"Algorithm mismatch: expected {expected_algorithm}, got {algorithm}")
            risk_level = "high"
        
        # Check for weak algorithms
        weak_algorithms = ["none", "HS256", "HS384", "HS512"]
        if algorithm in weak_algorithms:
            anomalies.append(f"Weak algorithm detected: {algorithm}")
            risk_level = "critical"
        
        # Check for algorithm switching
        if algorithm != expected_algorithm and algorithm != "none":
            anomalies.append("Algorithm switching detected")
            if risk_level != "critical":
                risk_level = "high"
        
        return {
            "algorithm": algorithm,
            "expected_algorithm": expected_algorithm,
            "anomalies": anomalies,
            "risk_level": risk_level,
            "anomaly_detected": len(anomalies) > 0
        }
    
    def analyze_payload_anomaly(self, token: str, known_roles: List[str] = None) -> Dict[str, any]:
        """
        Detect payload-based anomalies
        
        Args:
            token: JWT token to analyze
            known_roles: List of expected roles
            
        Returns:
            Dictionary with payload anomalies
        """
        features = self.extract_jwt_features(token)
        decoded = decode_jwt_without_verification(token)
        payload = decoded.get("payload", {})
        
        if known_roles is None:
            known_roles = ["user", "admin", "librarian", "member"]
        
        anomalies = []
        risk_level = "low"
        
        # Check for missing standard claims
        required_claims = ["exp", "iat", "sub"]
        for claim in required_claims:
            if not features.get(f"has_{claim}"):
                anomalies.append(f"Missing standard claim: {claim}")
                risk_level = "medium"
        
        # Check for unusual payload size
        if features["payload_size"] > 2000:
            anomalies.append(f"Unusually large payload: {features['payload_size']} bytes")
            risk_level = "medium"
        elif features["payload_size"] < 50:
            anomalies.append(f"Unusually small payload: {features['payload_size']} bytes")
            risk_level = "low"
        
        # Check for unusual claim count
        if features["claim_count"] > 20:
            anomalies.append(f"Unusually high claim count: {features['claim_count']}")
            risk_level = "medium"
        
        # Check for suspicious role values
        if features["has_role"]:
            role = features["role_value"]
            if isinstance(role, list):
                role_list = role
            else:
                role_list = [role]
            
            for r in role_list:
                if r not in known_roles:
                    anomalies.append(f"Unknown role detected: {r}")
                    risk_level = "high"
                
                # Check for privilege escalation attempts
                if "admin" in str(r).lower() and "user" in payload.get("original_role", ""):
                    anomalies.append("Possible privilege escalation attempt")
                    risk_level = "critical"
        
        # Check for unusual TTL
        if features.get("ttl_seconds"):
            ttl = features["ttl_seconds"]
            if ttl > 2592000:  # 30 days
                anomalies.append(f"Unusually long TTL: {ttl} seconds")
                risk_level = "medium"
            elif ttl < 60:  # Less than 1 minute
                anomalies.append(f"Unusually short TTL: {ttl} seconds")
                risk_level = "high"
        
        return {
            "payload_size": features["payload_size"],
            "claim_count": features["claim_count"],
            "role": features.get("role_value"),
            "ttl_seconds": features.get("ttl_seconds"),
            "anomalies": anomalies,
            "risk_level": risk_level,
            "anomaly_detected": len(anomalies) > 0
        }
    
    def analyze_signature_anomaly(self, token: str, has_valid_signature: bool = None) -> Dict[str, any]:
        """
        Detect signature-based anomalies
        
        Args:
            token: JWT token to analyze
            has_valid_signature: Whether signature verification passed
            
        Returns:
            Dictionary with signature anomalies
        """
        parts = token.split('.')
        
        anomalies = []
        risk_level = "low"
        
        # Check token format
        if len(parts) != 3:
            anomalies.append(f"Invalid JWT format: {len(parts)} parts instead of 3")
            risk_level = "critical"
        else:
            # Check signature presence
            if not parts[2]:
                anomalies.append("Missing signature (algorithm 'none' or malformed)")
                risk_level = "critical"
            elif len(parts[2]) < 20:
                anomalies.append("Unusually short signature")
                risk_level = "high"
        
        # Check for signature verification failure
        if has_valid_signature is False:
            anomalies.append("Signature verification failed")
            risk_level = "critical"
        
        return {
            "token_parts": len(parts),
            "has_signature": len(parts) == 3 and bool(parts[2]),
            "signature_length": len(parts[2]) if len(parts) == 3 else 0,
            "signature_valid": has_valid_signature,
            "anomalies": anomalies,
            "risk_level": risk_level,
            "anomaly_detected": len(anomalies) > 0
        }
    
    def comprehensive_analysis(self, token: str, expected_algorithm: str = "RS256",
                              known_roles: List[str] = None, 
                              signature_valid: bool = None) -> Dict[str, any]:
        """
        Perform comprehensive JWT anomaly analysis
        
        Args:
            token: JWT token to analyze
            expected_algorithm: Expected algorithm
            known_roles: Known valid roles
            signature_valid: Whether signature is valid
            
        Returns:
            Dictionary with comprehensive analysis
        """
        algorithm_analysis = self.analyze_algorithm_anomaly(token, expected_algorithm)
        payload_analysis = self.analyze_payload_anomaly(token, known_roles)
        signature_analysis = self.analyze_signature_anomaly(token, signature_valid)
        
        # Aggregate risk levels
        risk_scores = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }
        
        risk_values = [
            risk_scores.get(algorithm_analysis["risk_level"], 1),
            risk_scores.get(payload_analysis["risk_level"], 1),
            risk_scores.get(signature_analysis["risk_level"], 1),
        ]
        
        max_risk_score = max(risk_values)
        risk_level_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        overall_risk = risk_level_map[max_risk_score]
        
        # Collect all anomalies
        all_anomalies = (
            algorithm_analysis.get("anomalies", []) +
            payload_analysis.get("anomalies", []) +
            signature_analysis.get("anomalies", [])
        )
        
        # Determine action
        if overall_risk == "critical":
            action = "BLOCK_IMMEDIATELY"
        elif overall_risk == "high":
            action = "REQUIRE_REAUTHENTICATION"
        elif overall_risk == "medium":
            action = "LOG_AND_MONITOR"
        else:
            action = "ALLOW"
        
        comprehensive = {
            "timestamp": datetime.now().isoformat(),
            "token_length": len(token),
            "algorithm_analysis": algorithm_analysis,
            "payload_analysis": payload_analysis,
            "signature_analysis": signature_analysis,
            "total_anomalies": len(all_anomalies),
            "anomalies": all_anomalies,
            "overall_risk_level": overall_risk,
            "recommended_action": action,
            "is_suspicious": overall_risk in ["high", "critical"]
        }
        
        # Log suspicious tokens
        if comprehensive["is_suspicious"]:
            self.anomaly_log.append(comprehensive)
            logger.warning(f"Suspicious token detected: {action}")
        
        return comprehensive
    
    def train_baseline(self, clean_tokens: List[str]):
        """
        Train anomaly detector on clean (legitimate) tokens
        
        Args:
            clean_tokens: List of known legitimate tokens
        """
        logger.info(f"Training baseline on {len(clean_tokens)} clean tokens...")
        
        all_features = []
        
        for token in clean_tokens:
            try:
                features = self.extract_jwt_features(token)
                all_features.append(features)
            except:
                pass
        
        # Calculate baseline statistics
        if all_features:
            self.normal_patterns = {
                "avg_token_length": statistics.mean([f["token_length"] for f in all_features]),
                "avg_payload_size": statistics.mean([f["payload_size"] for f in all_features]),
                "avg_claim_count": statistics.mean([f["claim_count"] for f in all_features]),
                "common_algorithms": list(set(f["algorithm"] for f in all_features)),
                "baseline_tokens": len(all_features)
            }
            
            logger.info(f"Baseline trained: {self.normal_patterns}")
    
    def get_anomaly_report(self) -> Dict[str, any]:
        """
        Get comprehensive anomaly report
        
        Returns:
            Dictionary with anomaly statistics
        """
        return {
            "total_suspicious_tokens": len(self.anomaly_log),
            "baseline_patterns": self.normal_patterns,
            "recent_anomalies": self.anomaly_log[-10:] if self.anomaly_log else [],
            "timestamp": datetime.now().isoformat()
        }


def main():
    """Test JWT anomaly detection"""
    print("=" * 60)
    print("JWT ANOMALY DETECTION TEST")
    print("=" * 60)
    
    detector = JWTAnomalyDetector()
    
    # Test tokens
    valid_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIiLCJpYXQiOjE2MzAwMDAwMDAsImV4cCI6MTYzMDAwMzYwMH0.signature"
    weak_alg_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature"
    no_alg_token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyMTIzIn0."
    
    print("\n[1/3] Analyzing valid token...")
    analysis = detector.comprehensive_analysis(valid_token)
    print(f"  Risk level: {analysis['overall_risk_level']}")
    print(f"  Anomalies detected: {analysis['total_anomalies']}")
    print(f"  Action: {analysis['recommended_action']}")
    
    print("\n[2/3] Analyzing weak algorithm token...")
    analysis = detector.comprehensive_analysis(weak_alg_token)
    print(f"  Risk level: {analysis['overall_risk_level']}")
    print(f"  Anomalies: {len(analysis['anomalies'])}")
    print(f"  Action: {analysis['recommended_action']}")
    
    print("\n[3/3] Analyzing 'none' algorithm token...")
    analysis = detector.comprehensive_analysis(no_alg_token)
    print(f"  Risk level: {analysis['overall_risk_level']}")
    print(f"  Anomalies: {len(analysis['anomalies'])}")
    print(f"  Action: {analysis['recommended_action']}")
    
    # Get report
    print("\nAnomaly Report:")
    report = detector.get_anomaly_report()
    print(f"  Suspicious tokens detected: {report['total_suspicious_tokens']}")


if __name__ == "__main__":
    from core.logging_setup import initialize_all_loggers
    initialize_all_loggers()
    main()
