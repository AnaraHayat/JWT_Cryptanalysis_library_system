"""
Brute Force Attack Analysis for JWT Secrets
Analyzes and visualizes brute force attack effectiveness
"""

import json
import time
import hashlib
import math
from typing import Dict, List, Tuple
from pathlib import Path
import logging
import threading
from collections import defaultdict

from core.jwt_config import BACKENDS, ATTACK_CONFIG, DATA_PATHS, get_backend_url, API_ENDPOINTS
from core.logging_setup import get_logger, log_attack
from core.utils import save_csv_row, encode_jwt, save_json_data

logger = logging.getLogger(__name__)

class BruteForceAnalyzer:
    """Analyzes brute force attack feasibility and effectiveness"""
    
    def __init__(self, backend_name: str = "vulnerable"):
        """Initialize brute force analyzer"""
        self.backend = BACKENDS[backend_name]
        self.backend_name = backend_name
        self.attack_results = []
        self.crack_log = []
    
    def estimate_brute_force_feasibility(self, secret_entropy: float, wordlist_size: int) -> Dict[str, any]:
        """
        Estimate feasibility of brute force attack
        
        Args:
            secret_entropy: Entropy of the secret in bits
            wordlist_size: Size of wordlist to use
            
        Returns:
            Dictionary with feasibility estimates
        """
        # Calculate keyspace
        keyspace = 2 ** secret_entropy
        
        # Estimate attack scenarios
        scenarios = {
            "1K_attempts_sec": {
                "attempts_per_sec": 1_000,
                "attempts_for_success": keyspace / 2,  # Average case
            },
            "1M_attempts_sec": {
                "attempts_per_sec": 1_000_000,
                "attempts_for_success": keyspace / 2,
            },
            "1B_attempts_sec": {
                "attempts_per_sec": 1_000_000_000,
                "attempts_for_success": keyspace / 2,
            },
            "wordlist_attack": {
                "attempts_per_sec": 1_000_000,
                "attempts_for_success": wordlist_size,
            }
        }
        
        feasibility = {
            "secret_entropy_bits": secret_entropy,
            "keyspace": keyspace,
            "wordlist_size": wordlist_size,
            "scenarios": {}
        }
        
        for scenario_name, scenario_data in scenarios.items():
            attempts_needed = scenario_data["attempts_for_success"]
            rate = scenario_data["attempts_per_sec"]
            
            seconds_needed = attempts_needed / rate
            
            # Convert to human readable
            if seconds_needed < 1:
                time_str = f"{seconds_needed * 1e6:.0f} microseconds"
            elif seconds_needed < 60:
                time_str = f"{seconds_needed:.1f} seconds"
            elif seconds_needed < 3600:
                time_str = f"{seconds_needed / 60:.1f} minutes"
            elif seconds_needed < 86400:
                time_str = f"{seconds_needed / 3600:.1f} hours"
            else:
                time_str = f"{seconds_needed / 86400:.1f} days"
            
            feasibility["scenarios"][scenario_name] = {
                "attempts_per_second": rate,
                "attacks_for_success": int(attempts_needed),
                "time_to_crack_seconds": seconds_needed,
                "time_to_crack_human": time_str,
                "feasible": seconds_needed < 86400  # Less than 1 day
            }
        
        feasibility["recommendation"] = (
            "CRITICAL - Brute force highly feasible" if feasibility["scenarios"]["wordlist_attack"]["feasible"]
            else "WARNING - Brute force possible with GPU acceleration"
        )
        
        return feasibility
    
    def simulate_brute_force_attack(self, wordlist_file: str, correct_secret: str = None) -> Dict[str, any]:
        """
        Simulate a brute force attack using a wordlist
        
        Args:
            wordlist_file: Path to wordlist file
            correct_secret: The actual secret (if known, for validation)
            
        Returns:
            Dictionary with attack results
        """
        logger.info(f"[{self.backend_name}] Simulating brute force attack...")
        
        try:
            with open(wordlist_file, 'r') as f:
                wordlist = [word.strip() for word in f.readlines()]
        except FileNotFoundError:
            logger.error(f"Wordlist file not found: {wordlist_file}")
            return {}
        
        start_time = time.time()
        attempts = 0
        found = False
        found_secret = None
        found_at_attempt = None
        
        for idx, candidate in enumerate(wordlist):
            attempts += 1
            
            # In real scenario, would try this as JWT secret
            # For simulation, we compare with known secret
            if correct_secret and candidate == correct_secret:
                found = True
                found_secret = candidate
                found_at_attempt = attempts
                logger.info(f"[{self.backend_name}] Secret FOUND after {attempts} attempts: {candidate}")
                break
            
            # Log every 100th attempt
            if attempts % 100 == 0:
                elapsed = time.time() - start_time
                rate = attempts / elapsed
                logger.debug(f"Attempt {attempts}/{len(wordlist)} ({rate:.0f} attempts/sec)")
        
        elapsed_time = time.time() - start_time
        success_rate = (attempts / len(wordlist)) * 100
        
        result = {
            "wordlist_size": len(wordlist),
            "attempts": attempts,
            "elapsed_time_sec": elapsed_time,
            "attempts_per_sec": attempts / elapsed_time if elapsed_time > 0 else 0,
            "success": found,
            "found_secret": found_secret if found else None,
            "found_at_attempt": found_at_attempt,
            "success_rate_percent": success_rate if found else 0,
            "average_attempts_for_success": len(wordlist) / 2 if not found else attempts,
            "recommendation": "VULNERABLE - Secret found via wordlist" if found else "SAFE (against this wordlist)"
        }
        
        logger.info(f"[{self.backend_name}] Brute force simulation complete: "
                   f"{'SUCCESS' if found else 'FAILED'} in {elapsed_time:.2f} seconds")
        
        return result
    
    def analyze_dictionary_attack_feasibility(self, wordlist_file: str, secret_entropy: float) -> Dict[str, any]:
        """
        Analyze feasibility of dictionary attack against wordlist
        
        Args:
            wordlist_file: Path to wordlist file
            secret_entropy: Entropy of the secret
            
        Returns:
            Dictionary with attack analysis
        """
        try:
            with open(wordlist_file, 'r') as f:
                wordlist = [word.strip() for word in f.readlines()]
        except FileNotFoundError:
            logger.error(f"Wordlist file not found: {wordlist_file}")
            return {}
        
        wordlist_size = len(wordlist)
        keyspace = 2 ** secret_entropy
        
        # Dictionary attack probability
        success_probability = min(1.0, wordlist_size / keyspace)
        
        # Estimate with variations (common mutations)
        mutation_multiplier = 1000  # e.g., l33t speak, capitalization, etc.
        effective_search_space = wordlist_size * mutation_multiplier
        mutation_success_probability = min(1.0, effective_search_space / keyspace)
        
        analysis = {
            "wordlist_size": wordlist_size,
            "secret_entropy_bits": secret_entropy,
            "keyspace": keyspace,
            "success_probability": success_probability,
            "success_probability_percent": success_probability * 100,
            "success_probability_with_mutations": mutation_success_probability,
            "success_probability_with_mutations_percent": mutation_success_probability * 100,
            "verdict": (
                "HIGH RISK - Dictionary attack highly likely to succeed" if success_probability > 0.5
                else "MEDIUM RISK - Dictionary attack could succeed" if success_probability > 0.01
                else "LOW RISK - Dictionary attack unlikely"
            ),
            "top_10_likely_candidates": wordlist[:10] if len(wordlist) > 0 else []
        }
        
        return analysis
    
    def estimate_cracking_time_with_resources(self, secret_entropy: float) -> Dict[str, any]:
        """
        Estimate time to crack secret with various computational resources
        
        Args:
            secret_entropy: Entropy of secret in bits
            
        Returns:
            Dictionary with crack time estimates
        """
        keyspace = 2 ** secret_entropy
        
        resources = {
            "single_cpu": 1_000,  # 1K attempts/sec
            "multi_cpu": 100_000,  # 100K attempts/sec
            "gpu_single": 1_000_000,  # 1M attempts/sec
            "gpu_cluster": 1_000_000_000,  # 1B attempts/sec (10x GPUs)
            "distributed_botnet": 1_000_000_000_000,  # 1T attempts/sec (50K infected machines)
        }
        
        estimates = {
            "secret_entropy_bits": secret_entropy,
            "keyspace": keyspace,
            "resources": {}
        }
        
        for resource_name, attack_rate in resources.items():
            average_attempts = keyspace / 2
            seconds_to_crack = average_attempts / attack_rate
            
            if seconds_to_crack < 1:
                time_str = f"{seconds_to_crack * 1e6:.0f} μs"
                feasible = "YES (Trivial)"
            elif seconds_to_crack < 60:
                time_str = f"{seconds_to_crack:.1f}s"
                feasible = "YES (Easy)"
            elif seconds_to_crack < 3600:
                time_str = f"{seconds_to_crack / 60:.1f} min"
                feasible = "YES (Easy)"
            elif seconds_to_crack < 86400:
                time_str = f"{seconds_to_crack / 3600:.1f} hrs"
                feasible = "YES (Hard)"
            elif seconds_to_crack < 365.25 * 86400:
                time_str = f"{seconds_to_crack / 86400:.1f} days"
                feasible = "MAYBE"
            else:
                years = seconds_to_crack / (365.25 * 86400)
                time_str = f"{years:.1e} years"
                feasible = "NO (Infeasible)" if years > 1e6 else "MAYBE"
            
            estimates["resources"][resource_name] = {
                "attack_rate_attempts_per_sec": attack_rate,
                "time_to_crack_seconds": seconds_to_crack,
                "time_to_crack_human": time_str,
                "feasible": feasible
            }
        
        return estimates
    
    def save_brute_force_report(self, wordlist_file: str, secret_entropy: float, correct_secret: str = None):
        """
        Generate comprehensive brute force analysis report
        
        Args:
            wordlist_file: Path to wordlist
            secret_entropy: Entropy of secret
            correct_secret: Known secret for validation (optional)
        """
        logger.info(f"[{self.backend_name}] Generating brute force analysis report...")
        
        # Feasibility analysis
        feasibility = self.estimate_brute_force_feasibility(secret_entropy, self._get_wordlist_size(wordlist_file))
        
        # Dictionary attack analysis
        dict_analysis = self.analyze_dictionary_attack_feasibility(wordlist_file, secret_entropy)
        
        # Cracking time estimates
        crack_times = self.estimate_cracking_time_with_resources(secret_entropy)
        
        # Simulation (if secret provided)
        simulation = {}
        if correct_secret:
            simulation = self.simulate_brute_force_attack(wordlist_file, correct_secret)
        
        report = {
            "backend": self.backend_name,
            "feasibility": feasibility,
            "dictionary_attack": dict_analysis,
            "cracking_times": crack_times,
            "simulation": simulation,
            "summary": {
                "overall_risk": "CRITICAL" if dict_analysis["success_probability"] > 0.5 else "HIGH" if dict_analysis["success_probability"] > 0.01 else "MEDIUM",
                "recommendation": "CHANGE SECRET IMMEDIATELY" if dict_analysis["success_probability"] > 0.1 else "Use stronger secret"
            }
        }
        
        save_json_data(
            report,
            DATA_PATHS.get("brute_force_analysis", "data/brute_force_analysis.json")
        )
        
        logger.info(f"[{self.backend_name}] Report saved")
        return report
    
    @staticmethod
    def _get_wordlist_size(wordlist_file: str) -> int:
        """Get the size of a wordlist file"""
        try:
            with open(wordlist_file, 'r') as f:
                return len(f.readlines())
        except:
            return 0


def main():
    """Run brute force analysis"""
    from analysis.jwt_entropy_analysis import EntropyAnalyzer
    
    print("=" * 60)
    print("BRUTE FORCE ATTACK ANALYSIS")
    print("=" * 60)
    
    analyzer = BruteForceAnalyzer("vulnerable")
    
    # Known weak secret
    weak_secret = "library-secret-123"
    weak_secret_entropy = EntropyAnalyzer.estimate_secret_strength(weak_secret)["entropy_bits"]
    
    print(f"\n[1/4] Analyzing weak secret: {weak_secret}")
    print(f"  Entropy: {weak_secret_entropy:.2f} bits")
    
    # Analyze feasibility
    print("\n[2/4] Analyzing brute force feasibility...")
    feasibility = analyzer.estimate_brute_force_feasibility(weak_secret_entropy, 50)
    print(f"  Wordlist attack: {feasibility['scenarios']['wordlist_attack']['time_to_crack_human']}")
    print(f"  Feasible: {feasibility['scenarios']['wordlist_attack']['feasible']}")
    
    # Dictionary attack
    print("\n[3/4] Analyzing dictionary attack...")
    wordlist_file = "secrets/wordlist.txt"
    dict_analysis = analyzer.analyze_dictionary_attack_feasibility(wordlist_file, weak_secret_entropy)
    print(f"  Success probability: {dict_analysis['success_probability_percent']:.1f}%")
    print(f"  Verdict: {dict_analysis['verdict']}")
    
    # Cracking time estimates
    print("\n[4/4] Estimating cracking times...")
    crack_times = analyzer.estimate_cracking_time_with_resources(weak_secret_entropy)
    print(f"  Single CPU: {crack_times['resources']['single_cpu']['time_to_crack_human']}")
    print(f"  GPU Cluster: {crack_times['resources']['gpu_cluster']['time_to_crack_human']}")
    
    # Save comprehensive report
    report = analyzer.save_brute_force_report(wordlist_file, weak_secret_entropy, weak_secret)
    print(f"\nReport Summary:")
    print(f"  Overall Risk: {report['summary']['overall_risk']}")
    print(f"  Recommendation: {report['summary']['recommendation']}")


if __name__ == "__main__":
    from core.logging_setup import initialize_all_loggers
    initialize_all_loggers()
    main()
