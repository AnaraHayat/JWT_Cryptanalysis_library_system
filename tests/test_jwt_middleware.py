"""
Test Suite for JWT Whitelist Middleware and Anomaly Detector
Tests token validation, revocation, and anomaly detection
"""

import pytest
import json
import time
import tempfile
from pathlib import Path

from core.jwt_whitelist_middleware import JWTWhitelist, JWTBlacklist, JWTWhitelistMiddleware
from core.jwt_anomaly_detector import JWTAnomalyDetector
from core.utils import encode_jwt


class TestJWTWhitelist:
    """Test JWT whitelist functionality"""
    
    def test_add_token_to_whitelist(self):
        """Test adding token to whitelist"""
        with tempfile.TemporaryDirectory() as tmpdir:
            whitelist = JWTWhitelist(whitelist_file=Path(tmpdir) / "whitelist.json")
            
            test_token = "test.jwt.token"
            result = whitelist.add_token(test_token, user_id="user123")
            
            assert result is True
            assert whitelist.is_whitelisted(test_token) is True
    
    def test_whitelisted_token_validation(self):
        """Test validating whitelisted token"""
        with tempfile.TemporaryDirectory() as tmpdir:
            whitelist = JWTWhitelist(whitelist_file=Path(tmpdir) / "whitelist.json")
            
            test_token = "test.jwt.token"
            whitelist.add_token(test_token, user_id="user123")
            
            assert whitelist.is_whitelisted(test_token) is True
    
    def test_non_whitelisted_token_rejected(self):
        """Test that non-whitelisted tokens are rejected"""
        with tempfile.TemporaryDirectory() as tmpdir:
            whitelist = JWTWhitelist(whitelist_file=Path(tmpdir) / "whitelist.json")
            
            test_token = "test.jwt.token"
            
            assert whitelist.is_whitelisted(test_token) is False
    
    def test_revoke_token(self):
        """Test revoking a token"""
        with tempfile.TemporaryDirectory() as tmpdir:
            whitelist = JWTWhitelist(whitelist_file=Path(tmpdir) / "whitelist.json")
            
            test_token = "test.jwt.token"
            whitelist.add_token(test_token, user_id="user123")
            
            assert whitelist.is_whitelisted(test_token) is True
            
            # Revoke
            result = whitelist.revoke_token(test_token)
            assert result is True
            assert whitelist.is_whitelisted(test_token) is False
    
    def test_revoke_user_tokens(self):
        """Test revoking all tokens for a user"""
        with tempfile.TemporaryDirectory() as tmpdir:
            whitelist = JWTWhitelist(whitelist_file=Path(tmpdir) / "whitelist.json")
            
            user_id = "user123"
            
            # Add multiple tokens for same user
            for i in range(3):
                whitelist.add_token(f"token_{i}", user_id=user_id)
            
            # Revoke all
            revoked_count = whitelist.revoke_user_tokens(user_id)
            
            assert revoked_count == 3
    
    def test_expired_token_cleanup(self):
        """Test cleanup of expired tokens"""
        with tempfile.TemporaryDirectory() as tmpdir:
            whitelist = JWTWhitelist(whitelist_file=Path(tmpdir) / "whitelist.json")
            
            # Add token with very short TTL
            test_token = "test.jwt.token"
            whitelist.add_token(test_token, user_id="user123", ttl_seconds=1)
            
            # Wait for expiry
            time.sleep(2)
            
            # Should be expired
            assert whitelist.is_whitelisted(test_token) is False
    
    def test_whitelist_statistics(self):
        """Test getting whitelist statistics"""
        with tempfile.TemporaryDirectory() as tmpdir:
            whitelist = JWTWhitelist(whitelist_file=Path(tmpdir) / "whitelist.json")
            
            # Add tokens
            for i in range(5):
                whitelist.add_token(f"token_{i}", user_id=f"user_{i}")
            
            stats = whitelist.get_statistics()
            
            assert stats["total_tokens"] == 5
            assert stats["active_tokens"] == 5
            assert stats["unique_users"] == 5


class TestJWTBlacklist:
    """Test JWT blacklist functionality"""
    
    def test_add_to_blacklist(self):
        """Test adding token to blacklist"""
        with tempfile.TemporaryDirectory() as tmpdir:
            blacklist = JWTBlacklist(blacklist_file=Path(tmpdir) / "blacklist.json")
            
            test_token = "test.jwt.token"
            result = blacklist.add_revoked_token(test_token, user_id="user123", reason="user_logout")
            
            assert result is True
            assert blacklist.is_blacklisted(test_token) is True
    
    def test_non_blacklisted_token_allowed(self):
        """Test that non-blacklisted tokens are allowed"""
        with tempfile.TemporaryDirectory() as tmpdir:
            blacklist = JWTBlacklist(blacklist_file=Path(tmpdir) / "blacklist.json")
            
            test_token = "test.jwt.token"
            
            assert blacklist.is_blacklisted(test_token) is False
    
    def test_blacklist_statistics(self):
        """Test getting blacklist statistics"""
        with tempfile.TemporaryDirectory() as tmpdir:
            blacklist = JWTBlacklist(blacklist_file=Path(tmpdir) / "blacklist.json")
            
            # Add tokens
            for i in range(3):
                blacklist.add_revoked_token(f"token_{i}", reason="test")
            
            stats = blacklist.get_statistics()
            
            assert stats["total_blacklisted_tokens"] == 3


class TestJWTWhitelistMiddleware:
    """Test JWT whitelist middleware"""
    
    def test_middleware_registration(self):
        """Test token registration through middleware"""
        with tempfile.TemporaryDirectory() as tmpdir:
            middleware = JWTWhitelistMiddleware()
            
            test_token = "test.jwt.token"
            result = middleware.register_new_token(test_token, "user123")
            
            assert result is True
    
    def test_middleware_validation(self):
        """Test token validation through middleware"""
        with tempfile.TemporaryDirectory() as tmpdir:
            middleware = JWTWhitelistMiddleware()
            
            test_token = "test.jwt.token"
            middleware.register_new_token(test_token, "user123")
            
            result = middleware.validate_token(test_token)
            
            assert result["valid"] is True
    
    def test_middleware_logout(self):
        """Test token logout through middleware"""
        with tempfile.TemporaryDirectory() as tmpdir:
            middleware = JWTWhitelistMiddleware()
            
            test_token = "test.jwt.token"
            middleware.register_new_token(test_token, "user123")
            middleware.logout_token(test_token, "user123")
            
            result = middleware.validate_token(test_token)
            
            assert result["valid"] is False
    
    def test_middleware_security_report(self):
        """Test getting security report from middleware"""
        with tempfile.TemporaryDirectory() as tmpdir:
            middleware = JWTWhitelistMiddleware()
            
            report = middleware.get_security_report()
            
            assert "whitelist" in report
            assert "blacklist" in report
            assert "timestamp" in report


class TestJWTAnomalyDetector:
    """Test JWT anomaly detection"""
    
    def test_feature_extraction(self):
        """Test extracting features from JWT"""
        payload = {
            "sub": "user123",
            "role": "admin",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600
        }
        
        token = encode_jwt(payload, "secret")
        detector = JWTAnomalyDetector()
        
        features = detector.extract_jwt_features(token)
        
        assert "token_length" in features
        assert "algorithm" in features
        assert "payload_size" in features
        assert "claim_count" in features
        assert "has_exp" in features
    
    def test_algorithm_anomaly_detection_hs256(self):
        """Test detecting HS256 when RS256 is expected"""
        payload = {"sub": "user"}
        token = encode_jwt(payload, "secret", algorithm="HS256")
        
        detector = JWTAnomalyDetector()
        analysis = detector.analyze_algorithm_anomaly(token, expected_algorithm="RS256")
        
        assert analysis["anomaly_detected"] is True
        assert analysis["risk_level"] in ["high", "critical"]
    
    def test_algorithm_anomaly_detection_alg_none(self):
        """Test detecting alg:none attack"""
        import base64
        
        header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip('=')
        payload = base64.urlsafe_b64encode(b'{"sub":"user"}').decode().rstrip('=')
        token = f"{header}.{payload}."
        
        detector = JWTAnomalyDetector()
        analysis = detector.analyze_algorithm_anomaly(token, expected_algorithm="RS256")
        
        assert analysis["anomaly_detected"] is True
        assert analysis["risk_level"] == "critical"
    
    def test_payload_anomaly_missing_claims(self):
        """Test detecting missing claims"""
        # Minimal payload missing required claims
        payload = {"sub": "user"}  # Missing exp, iat, etc.
        token = encode_jwt(payload, "secret")
        
        detector = JWTAnomalyDetector()
        analysis = detector.analyze_payload_anomaly(token)
        
        assert analysis["anomaly_detected"] is True
        assert analysis["risk_level"] in ["medium", "high"]
    
    def test_payload_anomaly_unknown_role(self):
        """Test detecting unknown role"""
        payload = {
            "sub": "user",
            "role": "superuser",  # Not in known roles
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600
        }
        token = encode_jwt(payload, "secret")
        
        detector = JWTAnomalyDetector()
        known_roles = ["user", "admin", "librarian"]
        analysis = detector.analyze_payload_anomaly(token, known_roles=known_roles)
        
        assert analysis["anomaly_detected"] is True
    
    def test_signature_anomaly_detection(self):
        """Test detecting signature issues"""
        payload = {"sub": "user"}
        token = encode_jwt(payload, "secret")
        
        detector = JWTAnomalyDetector()
        
        # Valid signature
        analysis = detector.analyze_signature_anomaly(token, has_valid_signature=True)
        assert analysis["anomaly_detected"] is False
        
        # Invalid signature
        analysis = detector.analyze_signature_anomaly(token, has_valid_signature=False)
        assert analysis["anomaly_detected"] is True
    
    def test_comprehensive_analysis(self):
        """Test comprehensive anomaly analysis"""
        payload = {
            "sub": "user",
            "role": "user",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600
        }
        token = encode_jwt(payload, "secret", algorithm="HS256")
        
        detector = JWTAnomalyDetector()
        analysis = detector.comprehensive_analysis(
            token,
            expected_algorithm="RS256",
            known_roles=["user", "admin"]
        )
        
        assert "overall_risk_level" in analysis
        assert "total_anomalies" in analysis
        assert "is_suspicious" in analysis
        assert "recommended_action" in analysis
    
    def test_baseline_training(self):
        """Test training baseline on clean tokens"""
        detector = JWTAnomalyDetector()
        
        # Generate clean tokens
        clean_tokens = []
        for i in range(5):
            payload = {"sub": f"user{i}", "role": "user"}
            token = encode_jwt(payload, "secret")
            clean_tokens.append(token)
        
        detector.train_baseline(clean_tokens)
        
        assert len(detector.normal_patterns) > 0
        assert detector.normal_patterns["baseline_tokens"] == 5
    
    def test_anomaly_report(self):
        """Test getting anomaly report"""
        detector = JWTAnomalyDetector()
        
        report = detector.get_anomaly_report()
        
        assert "total_suspicious_tokens" in report
        assert "baseline_patterns" in report
        assert "timestamp" in report


class TestAnomalyDetectionAccuracy:
    """Test overall accuracy of anomaly detection"""
    
    def test_normal_token_not_suspicious(self):
        """Test that normal tokens are not flagged"""
        payload = {
            "sub": "user",
            "role": "user",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600
        }
        token = encode_jwt(payload, "secret", algorithm="HS256")
        
        detector = JWTAnomalyDetector()
        analysis = detector.comprehensive_analysis(token, expected_algorithm="HS256")
        
        # With correct algorithm, should have low risk
        assert analysis["overall_risk_level"] in ["low", "medium"]
    
    def test_malicious_token_suspicious(self):
        """Test that malicious tokens are flagged"""
        # Multiple attack indicators
        payload = {
            "sub": "user",
            "role": "admin",  # Privilege escalation
            "bypass_auth": True,  # Suspicious claim
            "iat": int(time.time()),
            "exp": int(time.time()) + 86400 * 365  # Unusually long TTL
        }
        token = encode_jwt(payload, "secret", algorithm="HS256")
        
        detector = JWTAnomalyDetector()
        analysis = detector.comprehensive_analysis(token, expected_algorithm="RS256")
        
        # Should be flagged as suspicious
        assert analysis["is_suspicious"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
