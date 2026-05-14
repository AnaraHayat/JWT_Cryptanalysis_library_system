"""
Test Suite for Analysis Modules
Tests entropy analysis, brute force analysis, and timing attacks
"""

import pytest
import time
import tempfile
from pathlib import Path

from analysis.jwt_entropy_analysis import EntropyAnalyzer
from analysis.brute_force_analysis_library import BruteForceAnalyzer
from core.utils import encode_jwt


class TestEntropyAnalyzer:
    """Test entropy analysis"""
    
    def test_calculate_entropy_weak_secret(self):
        """Test entropy of weak secret"""
        analyzer = EntropyAnalyzer()
        entropy = analyzer.calculate_entropy("123456")
        
        assert entropy < 10  # Weak secret should have low entropy
    
    def test_calculate_entropy_strong_secret(self):
        """Test entropy of strong secret"""
        analyzer = EntropyAnalyzer()
        entropy = analyzer.calculate_entropy("xK9$mL@2pQ#vJ8&nR%4wE1^sY6~uT3")
        
        assert entropy > 4.0  # Strong secret should have higher entropy
    
    def test_calculate_entropy_zero_for_uniform(self):
        """Test entropy is zero for uniform strings"""
        analyzer = EntropyAnalyzer()
        entropy = analyzer.calculate_entropy("aaaa")
        
        assert entropy == 0.0
    
    def test_estimate_secret_strength_weak(self):
        """Test estimating weak secret strength"""
        analyzer = EntropyAnalyzer()
        strength = analyzer.estimate_secret_strength("123456")
        
        assert strength["entropy_bits"] < 20
        assert "WEAK" in strength["recommendation"]
        assert strength["crack_difficulty"] in ["Trivial", "Easy"]
    
    def test_estimate_secret_strength_strong(self):
        """Test estimating strong secret strength"""
        analyzer = EntropyAnalyzer()
        strength = analyzer.estimate_secret_strength("xK9$mL@2pQ#vJ8&nR%4wE1^sY6~uT3")
        
        assert strength["entropy_bits"] > 100
        assert strength["crack_difficulty"] in ["Hard", "Very Hard", "Infeasible"]
    
    def test_secret_strength_has_charset_info(self):
        """Test secret strength analysis includes charset info"""
        analyzer = EntropyAnalyzer()
        strength = analyzer.estimate_secret_strength("aB1!")
        
        assert "char_types" in strength
        assert strength["char_types"]["lowercase"] is True
        assert strength["char_types"]["uppercase"] is True
        assert strength["char_types"]["digits"] is True
        assert strength["char_types"]["special"] is True
    
    def test_analyze_jwt_token(self):
        """Test analyzing JWT token"""
        payload = {"sub": "user"}
        token = encode_jwt(payload, "secret")
        
        analyzer = EntropyAnalyzer()
        analysis = analyzer.analyze_jwt_token(token)
        
        assert "token_length" in analysis
        assert "header" in analysis
        assert "payload" in analysis
        assert "signature" in analysis
        assert "algorithm" in analysis
        assert "total_entropy_bits" in analysis
    
    def test_analyze_signature_strength_hs256(self):
        """Test analyzing HS256 signature strength"""
        analyzer = EntropyAnalyzer()
        analysis = analyzer.analyze_signature_strength("HS256", "weak-secret")
        
        assert analysis["algorithm"] == "HS256"
        assert analysis["algorithm_type"] == "symmetric"
        assert "secret_analysis" in analysis
    
    def test_analyze_signature_strength_rs256(self):
        """Test analyzing RS256 signature strength"""
        analyzer = EntropyAnalyzer()
        # Dummy key for testing
        rsa_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----"
        analysis = analyzer.analyze_signature_strength("RS256", rsa_key)
        
        assert analysis["algorithm"] == "RS256"
        assert analysis["algorithm_type"] == "asymmetric"
    
    def test_analyze_signature_strength_alg_none(self):
        """Test detecting alg:none vulnerability"""
        analyzer = EntropyAnalyzer()
        analysis = analyzer.analyze_signature_strength("none", "")
        
        assert "CRITICAL" in analysis["vulnerability"]


class TestBruteForceAnalyzer:
    """Test brute force analysis"""
    
    def test_estimate_brute_force_feasibility(self):
        """Test estimating brute force feasibility"""
        analyzer = BruteForceAnalyzer("vulnerable")
        
        # Test with weak secret (20-bit entropy)
        feasibility = analyzer.estimate_brute_force_feasibility(20, 50)
        
        assert "keyspace" in feasibility
        assert "scenarios" in feasibility
        assert feasibility["keyspace"] == 2 ** 20
    
    def test_feasibility_wordlist_attack_weak_secret(self):
        """Test feasibility of wordlist attack on weak secret"""
        analyzer = BruteForceAnalyzer("vulnerable")
        
        feasibility = analyzer.estimate_brute_force_feasibility(20, 50)
        
        wordlist_scenario = feasibility["scenarios"]["wordlist_attack"]
        
        # Should be feasible (less than 1 day)
        assert wordlist_scenario["feasible"] is True
        assert wordlist_scenario["time_to_crack_seconds"] < 86400
    
    def test_feasibility_brute_force_strong_secret(self):
        """Test feasibility of brute force on strong secret"""
        analyzer = BruteForceAnalyzer("vulnerable")
        
        # 128-bit entropy (typical for strong secrets)
        feasibility = analyzer.estimate_brute_force_feasibility(128, 50)
        
        gpu_scenario = feasibility["scenarios"]["gpu_cluster"]
        
        # Should NOT be feasible
        assert gpu_scenario["time_to_crack_seconds"] > 86400
    
    def test_estimate_cracking_time_with_resources(self):
        """Test cracking time estimation with various resources"""
        analyzer = BruteForceAnalyzer("vulnerable")
        
        estimates = analyzer.estimate_cracking_time_with_resources(20)
        
        assert "resources" in estimates
        assert "single_cpu" in estimates["resources"]
        assert "gpu_cluster" in estimates["resources"]
        
        # GPU should be faster than CPU
        cpu_time = estimates["resources"]["single_cpu"]["time_to_crack_seconds"]
        gpu_time = estimates["resources"]["gpu_cluster"]["time_to_crack_seconds"]
        
        assert gpu_time < cpu_time
    
    def test_dictionary_attack_feasibility_weak_secret(self):
        """Test dictionary attack feasibility on weak secret"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create wordlist
            wordlist_path = Path(tmpdir) / "wordlist.txt"
            with open(wordlist_path, 'w') as f:
                for i in range(100):
                    f.write(f"password{i}\n")
            
            analyzer = BruteForceAnalyzer("vulnerable")
            
            analysis = analyzer.analyze_dictionary_attack_feasibility(
                str(wordlist_path),
                secret_entropy=20  # Weak secret
            )
            
            assert "success_probability" in analysis
            assert analysis["success_probability"] > 0.01
    
    def test_dictionary_attack_feasibility_strong_secret(self):
        """Test dictionary attack feasibility on strong secret"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create wordlist
            wordlist_path = Path(tmpdir) / "wordlist.txt"
            with open(wordlist_path, 'w') as f:
                for i in range(1000):
                    f.write(f"password{i}\n")
            
            analyzer = BruteForceAnalyzer("vulnerable")
            
            analysis = analyzer.analyze_dictionary_attack_feasibility(
                str(wordlist_path),
                secret_entropy=256  # Strong secret
            )
            
            assert "success_probability" in analysis
            assert analysis["success_probability"] < 0.000001
    
    def test_brute_force_simulation(self):
        """Test brute force simulation"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create wordlist with target secret
            wordlist_path = Path(tmpdir) / "wordlist.txt"
            secret = "library-secret-123"
            
            with open(wordlist_path, 'w') as f:
                for i in range(100):
                    f.write(f"password{i}\n")
                f.write(f"{secret}\n")  # Include target
            
            analyzer = BruteForceAnalyzer("vulnerable")
            
            result = analyzer.simulate_brute_force_attack(
                str(wordlist_path),
                correct_secret=secret
            )
            
            assert result["success"] is True
            assert result["found_secret"] == secret
            assert result["found_at_attempt"] <= 110


class TestTimingAttackAnalysis:
    """Test timing attack analysis"""
    
    def test_estimate_attack_scenario_cpu(self):
        """Test estimating attack time for CPU"""
        analyzer = BruteForceAnalyzer("vulnerable")
        
        feasibility = analyzer.estimate_brute_force_feasibility(20, 50)
        cpu_scenario = feasibility["scenarios"]["1K_attempts_sec"]
        
        assert "attempts_per_sec" in cpu_scenario
        assert cpu_scenario["attempts_per_sec"] == 1000
        assert "time_to_crack_human" in cpu_scenario
    
    def test_estimate_attack_scenario_gpu(self):
        """Test estimating attack time for GPU"""
        analyzer = BruteForceAnalyzer("vulnerable")
        
        feasibility = analyzer.estimate_brute_force_feasibility(20, 50)
        gpu_scenario = feasibility["scenarios"]["1B_attempts_sec"]
        
        assert "attempts_per_sec" in gpu_scenario
        assert gpu_scenario["attempts_per_sec"] == 1000000000


class TestEntropyVsAttackFeasibility:
    """Test relationship between entropy and attack feasibility"""
    
    def test_low_entropy_high_feasibility(self):
        """Test that low entropy leads to high attack feasibility"""
        analyzer = BruteForceAnalyzer("vulnerable")
        
        # 20-bit entropy (very weak)
        feasibility_weak = analyzer.estimate_brute_force_feasibility(20, 50)
        
        assert feasibility_weak["scenarios"]["wordlist_attack"]["feasible"] is True
        assert feasibility_weak["recommendation"] == "CRITICAL - Brute force highly feasible"
    
    def test_high_entropy_low_feasibility(self):
        """Test that high entropy leads to low attack feasibility"""
        analyzer = BruteForceAnalyzer("vulnerable")
        
        # 256-bit entropy (very strong)
        feasibility_strong = analyzer.estimate_brute_force_feasibility(256, 50)
        
        assert feasibility_strong["scenarios"]["wordlist_attack"]["feasible"] is False
        assert "WARNING" in feasibility_strong["recommendation"] or "CRITICAL" not in feasibility_strong["recommendation"]


class TestCrackTimeFormatting:
    """Test crack time formatting"""
    
    def test_format_microseconds(self):
        """Test formatting very short crack times"""
        analyzer = BruteForceAnalyzer("vulnerable")
        
        # Very weak (1-bit entropy)
        feasibility = analyzer.estimate_brute_force_feasibility(1, 50)
        time_str = feasibility["scenarios"]["1B_attempts_sec"]["time_to_crack_human"]
        
        assert "microsecond" in time_str.lower() or "us" in time_str.lower()
    
    def test_format_years(self):
        """Test formatting very long crack times"""
        analyzer = BruteForceAnalyzer("vulnerable")
        
        # Very strong (512-bit entropy)
        feasibility = analyzer.estimate_brute_force_feasibility(512, 50)
        time_str = feasibility["scenarios"]["single_cpu"]["time_to_crack_human"]
        
        assert "year" in time_str.lower() or "e+" in time_str.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
