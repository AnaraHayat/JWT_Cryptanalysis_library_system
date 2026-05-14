"""
Timing Side-Channel Analysis of JWT Verification
Analyzes response time patterns to detect timing leakage vulnerabilities
"""

import requests
import json
import time
import statistics
from typing import Dict, List, Tuple
from pathlib import Path
import logging

from core.jwt_config import BACKENDS, ATTACK_CONFIG, DATA_PATHS, get_backend_url, API_ENDPOINTS
from core.logging_setup import get_logger, log_attack
from core.utils import save_csv_row, decode_jwt_without_verification, save_json_data

logger = logging.getLogger(__name__)

class TimingAttacker:
    """Timing side-channel attack framework for JWT"""
    
    def __init__(self, backend_name: str = "vulnerable"):
        """Initialize timing attacker"""
        self.backend = BACKENDS[backend_name]
        self.backend_name = backend_name
        self.timing_results = []
    
    def measure_jwt_verification_time(self, token: str, num_samples: int = 100) -> Dict[str, float]:
        """
        Measure JWT verification response times
        
        Args:
            token: JWT token to test
            num_samples: Number of timing samples to collect
            
        Returns:
            Dictionary with timing statistics
        """
        times = []
        endpoint = self.backend["url"] + API_ENDPOINTS[self.backend_name]["books_protected"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Warmup requests
        for _ in range(ATTACK_CONFIG["timing_warmup_samples"]):
            try:
                requests.get(endpoint, headers=headers, timeout=5)
            except:
                pass
        
        # Measure actual requests
        logger.info(f"[{self.backend_name}] Collecting {num_samples} timing samples...")
        
        for i in range(num_samples):
            try:
                start = time.perf_counter()
                response = requests.get(endpoint, headers=headers, timeout=5)
                elapsed_ms = (time.perf_counter() - start) * 1000
                times.append(elapsed_ms)
                
                # Log to CSV
                save_csv_row(
                    DATA_PATHS["timing_dataset"],
                    {
                        "timestamp": time.time(),
                        "backend": self.backend_name,
                        "request_number": i + 1,
                        "response_time_ms": elapsed_ms,
                        "status_code": response.status_code,
                        "is_valid_token": response.status_code < 400
                    },
                    headers=["timestamp", "backend", "request_number", "response_time_ms", "status_code", "is_valid_token"]
                )
            except Exception as e:
                logger.error(f"Timing measurement error: {e}")
        
        if times:
            stats = {
                "backend": self.backend_name,
                "token_type": "valid",
                "samples": len(times),
                "min_ms": min(times),
                "max_ms": max(times),
                "mean_ms": statistics.mean(times),
                "median_ms": statistics.median(times),
                "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0,
                "variance_ms": statistics.variance(times) if len(times) > 1 else 0,
            }
            
            logger.info(f"[{self.backend_name}] Timing stats: mean={stats['mean_ms']:.2f}ms, "
                       f"stdev={stats['stdev_ms']:.2f}ms, variance={stats['variance_ms']:.2f}ms")
            
            return stats
        
        return {}
    
    def analyze_timing_variance(self) -> Dict[str, any]:
        """
        Analyze timing variance for side-channel detection
        
        Returns:
            Dictionary with timing analysis
        """
        # Read timing data
        timing_file = Path(DATA_PATHS["timing_dataset"])
        if not timing_file.exists():
            logger.warning("No timing data to analyze")
            return {}
        
        try:
            import csv
            times = []
            with open(timing_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        times.append(float(row["response_time_ms"]))
                    except (ValueError, KeyError):
                        pass
            
            if not times:
                return {}
            
            # Statistical analysis
            mean = statistics.mean(times)
            stdev = statistics.stdev(times) if len(times) > 1 else 0
            median = statistics.median(times)
            
            # Coefficient of variation (ratio of stdev to mean)
            cv = (stdev / mean) if mean > 0 else 0
            
            analysis = {
                "backend": self.backend_name,
                "total_samples": len(times),
                "mean_ms": mean,
                "median_ms": median,
                "stdev_ms": stdev,
                "variance_ms": statistics.variance(times) if len(times) > 1 else 0,
                "min_ms": min(times),
                "max_ms": max(times),
                "range_ms": max(times) - min(times),
                "coefficient_of_variation": cv,
                "interpretation": "High variance - no timing side-channel detectable" if cv > 0.2 else "Low variance - timing side-channel may be present"
            }
            
            logger.info(f"[{self.backend_name}] Timing variance analysis: CV={cv:.2%}")
            
            return analysis
        except Exception as e:
            logger.error(f"Error analyzing timing variance: {e}")
            return {}
    
    def detect_timing_differences(self, valid_token: str, invalid_token: str) -> Dict[str, any]:
        """
        Detect differences between valid and invalid token verification times
        
        Args:
            valid_token: Valid JWT token
            invalid_token: Invalid JWT token (wrong signature or forged)
            
        Returns:
            Dictionary with comparison results
        """
        endpoint = self.backend["url"] + API_ENDPOINTS[self.backend_name]["books_protected"]
        num_samples = 50
        
        valid_times = []
        invalid_times = []
        
        logger.info(f"[{self.backend_name}] Comparing valid vs invalid token verification times...")
        
        # Test valid token
        for i in range(num_samples):
            try:
                headers = {"Authorization": f"Bearer {valid_token}"}
                start = time.perf_counter()
                response = requests.get(endpoint, headers=headers, timeout=5)
                elapsed_ms = (time.perf_counter() - start) * 1000
                valid_times.append(elapsed_ms)
            except:
                pass
        
        # Test invalid token
        for i in range(num_samples):
            try:
                headers = {"Authorization": f"Bearer {invalid_token}"}
                start = time.perf_counter()
                response = requests.get(endpoint, headers=headers, timeout=5)
                elapsed_ms = (time.perf_counter() - start) * 1000
                invalid_times.append(elapsed_ms)
            except:
                pass
        
        if valid_times and invalid_times:
            valid_mean = statistics.mean(valid_times)
            invalid_mean = statistics.mean(invalid_times)
            valid_stdev = statistics.stdev(valid_times) if len(valid_times) > 1 else 0
            invalid_stdev = statistics.stdev(invalid_times) if len(invalid_times) > 1 else 0
            
            # Simple t-test simulation
            time_diff = abs(valid_mean - invalid_mean)
            pooled_stdev = statistics.sqrt((valid_stdev**2 + invalid_stdev**2) / 2)
            z_score = time_diff / pooled_stdev if pooled_stdev > 0 else 0
            
            comparison = {
                "backend": self.backend_name,
                "valid_token": {
                    "samples": len(valid_times),
                    "mean_ms": valid_mean,
                    "stdev_ms": valid_stdev,
                    "min_ms": min(valid_times),
                    "max_ms": max(valid_times)
                },
                "invalid_token": {
                    "samples": len(invalid_times),
                    "mean_ms": invalid_mean,
                    "stdev_ms": invalid_stdev,
                    "min_ms": min(invalid_times),
                    "max_ms": max(invalid_times)
                },
                "difference": {
                    "mean_diff_ms": time_diff,
                    "percent_diff": (time_diff / valid_mean * 100) if valid_mean > 0 else 0,
                    "z_score": z_score,
                    "statistically_significant": z_score > 2.0  # Rough threshold
                },
                "interpretation": "Potential timing side-channel" if z_score > 2.0 else "No significant timing difference detected"
            }
            
            logger.info(f"[{self.backend_name}] Valid: {valid_mean:.2f}ms ± {valid_stdev:.2f}ms | "
                       f"Invalid: {invalid_mean:.2f}ms ± {invalid_stdev:.2f}ms | "
                       f"Difference: {time_diff:.2f}ms ({comparison['difference']['percent_diff']:.1f}%)")
            
            return comparison
        
        return {}
    
    def measure_invalid_token_times(self, num_samples: int = 100) -> Dict[str, float]:
        """
        Measure verification times for invalid tokens
        
        Args:
            num_samples: Number of measurements
            
        Returns:
            Timing statistics for invalid tokens
        """
        times = []
        endpoint = self.backend["url"] + API_ENDPOINTS[self.backend_name]["books_protected"]
        
        # Use various invalid tokens
        invalid_tokens = [
            "invalid.token.here",
            "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiaGFjayJ9.",
            "x" * 100,
            "malformed token",
        ]
        
        logger.info(f"[{self.backend_name}] Measuring verification times for invalid tokens...")
        
        for i in range(num_samples):
            try:
                invalid_token = invalid_tokens[i % len(invalid_tokens)]
                headers = {"Authorization": f"Bearer {invalid_token}"}
                start = time.perf_counter()
                response = requests.get(endpoint, headers=headers, timeout=5)
                elapsed_ms = (time.perf_counter() - start) * 1000
                times.append(elapsed_ms)
            except Exception as e:
                logger.debug(f"Invalid token test error: {e}")
        
        if times:
            stats = {
                "backend": self.backend_name,
                "token_type": "invalid",
                "samples": len(times),
                "min_ms": min(times),
                "max_ms": max(times),
                "mean_ms": statistics.mean(times),
                "median_ms": statistics.median(times),
                "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0,
            }
            
            logger.info(f"[{self.backend_name}] Invalid token timing: mean={stats['mean_ms']:.2f}ms")
            
            return stats
        
        return {}


def main():
    """Run timing analysis"""
    from attacks.hijack_library_tokens import JWTAttacker
    
    # Test vulnerable backend
    print("=" * 60)
    print("TIMING ANALYSIS - JWT VERIFICATION")
    print("=" * 60)
    
    attacker = JWTAttacker("vulnerable")
    timing_attacker = TimingAttacker("vulnerable")
    
    # Get valid token
    token = attacker.get_valid_token()
    if not token:
        logger.error("Could not obtain valid token")
        return
    
    # Measure valid token times
    print("\n[1/3] Measuring valid token verification times...")
    valid_stats = timing_attacker.measure_jwt_verification_time(token, num_samples=50)
    print(f"Valid token: {valid_stats['mean_ms']:.2f}ms ± {valid_stats['stdev_ms']:.2f}ms")
    
    # Measure invalid token times
    print("\n[2/3] Measuring invalid token verification times...")
    invalid_stats = timing_attacker.measure_invalid_token_times(num_samples=50)
    print(f"Invalid token: {invalid_stats['mean_ms']:.2f}ms ± {invalid_stats['stdev_ms']:.2f}ms")
    
    # Compare timings
    print("\n[3/3] Comparing timing differences...")
    comparison = timing_attacker.detect_timing_differences(token, "invalid.token.here")
    print(json.dumps(comparison, indent=2))
    
    # Analyze variance
    print("\n[4/4] Analyzing timing variance...")
    variance_analysis = timing_attacker.analyze_timing_variance()
    print(json.dumps(variance_analysis, indent=2))
    
    # Save results
    results = {
        "valid_token_stats": valid_stats,
        "invalid_token_stats": invalid_stats,
        "comparison": comparison,
        "variance_analysis": variance_analysis
    }
    
    save_json_data(results, DATA_PATHS["timing_dataset"].replace(".csv", "_analysis.json"))
    print(f"\nResults saved to {DATA_PATHS['timing_dataset']}")


if __name__ == "__main__":
    from core.logging_setup import initialize_all_loggers
    initialize_all_loggers()
    main()
