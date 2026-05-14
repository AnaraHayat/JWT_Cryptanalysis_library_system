"""
JWT Token Entropy Analysis
Analyzes cryptographic strength and entropy of JWT components
"""

import json
import math
import string
from typing import Dict, List, Tuple
from pathlib import Path
import logging
import base64

from core.jwt_config import DATA_PATHS
from core.logging_setup import get_logger, log_attack
from core.utils import save_json_data, save_csv_row, decode_jwt_without_verification

logger = logging.getLogger(__name__)

class EntropyAnalyzer:
    """Analyzes entropy of JWT tokens and their components"""
    
    @staticmethod
    def calculate_entropy(data: str) -> float:
        """
        Calculate Shannon entropy of a string
        
        Args:
            data: String to analyze
            
        Returns:
            Entropy value in bits
        """
        if not data:
            return 0.0
        
        # Calculate frequency of each character
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate Shannon entropy
        entropy = 0.0
        data_len = len(data)
        for count in freq.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def estimate_secret_strength(secret: str) -> Dict[str, any]:
        """
        Estimate cryptographic strength of a secret
        
        Args:
            secret: Secret string to analyze
            
        Returns:
            Dictionary with strength metrics
        """
        entropy = EntropyAnalyzer.calculate_entropy(secret)
        
        # Estimate keyspace
        charset_size = 0
        has_lower = any(c.islower() for c in secret)
        has_upper = any(c.isupper() for c in secret)
        has_digit = any(c.isdigit() for c in secret)
        has_special = any(c in string.punctuation for c in secret)
        
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32
        
        # Calculate theoretical maximum entropy
        if charset_size > 0:
            max_entropy = len(secret) * math.log2(charset_size)
        else:
            max_entropy = 0
        
        # Brute force resistance
        attempts_for_crack = 2 ** entropy if entropy > 0 else 1
        
        # Estimate crack time at 1 billion attempts/sec
        seconds_to_crack = attempts_for_crack / 1e9
        
        # Convert to human readable format
        if seconds_to_crack < 1:
            crack_time_str = f"{seconds_to_crack * 1e6:.1f} microseconds"
            crack_difficulty = "Trivial"
        elif seconds_to_crack < 60:
            crack_time_str = f"{seconds_to_crack:.1f} seconds"
            crack_difficulty = "Trivial"
        elif seconds_to_crack < 3600:
            crack_time_str = f"{seconds_to_crack / 60:.1f} minutes"
            crack_difficulty = "Easy"
        elif seconds_to_crack < 86400:
            crack_time_str = f"{seconds_to_crack / 3600:.1f} hours"
            crack_difficulty = "Moderate"
        elif seconds_to_crack < 31536000:  # 1 year
            crack_time_str = f"{seconds_to_crack / 86400:.1f} days"
            crack_difficulty = "Hard"
        else:
            years = seconds_to_crack / 31536000
            crack_time_str = f"{years:.1e} years"
            crack_difficulty = "Very Hard" if years < 1e12 else "Infeasible"
        
        return {
            "secret": secret[:10] + "***" if len(secret) > 10 else "***",  # Hide actual secret
            "length": len(secret),
            "entropy_bits": entropy,
            "max_entropy_bits": max_entropy,
            "entropy_efficiency": (entropy / max_entropy * 100) if max_entropy > 0 else 0,
            "charset_size": charset_size,
            "char_types": {
                "lowercase": has_lower,
                "uppercase": has_upper,
                "digits": has_digit,
                "special": has_special
            },
            "attempts_for_50_percent": 2 ** (entropy - 1) if entropy > 0 else 0,
            "attempts_for_crack": int(attempts_for_crack),
            "crack_time_at_1B_attempts_sec": seconds_to_crack,
            "crack_time_human": crack_time_str,
            "crack_difficulty": crack_difficulty,
            "recommendation": "WEAK - Use stronger secret" if entropy < 128 else "ACCEPTABLE" if entropy < 256 else "STRONG"
        }
    
    @staticmethod
    def analyze_jwt_token(token: str) -> Dict[str, any]:
        """
        Analyze entropy and structure of a JWT token
        
        Args:
            token: JWT token to analyze
            
        Returns:
            Dictionary with token analysis
        """
        parts = token.split('.')
        if len(parts) != 3:
            logger.warning(f"Invalid JWT format: {len(parts)} parts")
            return {}
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Decode without verification
        decoded = decode_jwt_without_verification(token)
        
        analysis = {
            "token_length": len(token),
            "header": {
                "encoded_length": len(header_b64),
                "entropy_bits": EntropyAnalyzer.calculate_entropy(header_b64),
                "content": decoded.get("header", {})
            },
            "payload": {
                "encoded_length": len(payload_b64),
                "entropy_bits": EntropyAnalyzer.calculate_entropy(payload_b64),
                "content": decoded.get("payload", {})
            },
            "signature": {
                "encoded_length": len(signature_b64),
                "entropy_bits": EntropyAnalyzer.calculate_entropy(signature_b64),
                "content": "***" if signature_b64 else "NONE"
            },
            "algorithm": decoded.get("header", {}).get("alg", "unknown"),
            "signature_present": bool(signature_b64),
            "total_entropy_bits": (
                EntropyAnalyzer.calculate_entropy(header_b64) +
                EntropyAnalyzer.calculate_entropy(payload_b64) +
                EntropyAnalyzer.calculate_entropy(signature_b64)
            )
        }
        
        return analysis
    
    @staticmethod
    def analyze_signature_strength(algorithm: str, secret_or_key: str) -> Dict[str, any]:
        """
        Analyze cryptographic strength of JWT signature
        
        Args:
            algorithm: JWT algorithm (HS256, RS256, etc.)
            secret_or_key: Secret key or public key
            
        Returns:
            Dictionary with signature strength analysis
        """
        analysis = {
            "algorithm": algorithm,
            "algorithm_type": "symmetric" if algorithm.startswith("HS") else "asymmetric" if algorithm.startswith("RS") else "unknown",
        }
        
        if algorithm.startswith("HS"):
            # HMAC-based signatures rely on secret strength
            analysis["secret_analysis"] = EntropyAnalyzer.estimate_secret_strength(secret_or_key)
            analysis["vulnerability"] = "Weak secret makes brute force feasible" if analysis["secret_analysis"]["entropy_bits"] < 128 else "Strong secret"
        
        elif algorithm.startswith("RS"):
            # RSA-based signatures
            # Try to extract key size
            if isinstance(secret_or_key, str):
                if "BEGIN PUBLIC KEY" in secret_or_key or "BEGIN PRIVATE KEY" in secret_or_key:
                    # Estimate RSA key size
                    key_lines = [l for l in secret_or_key.split('\n') if l and not l.startswith('-----')]
                    if key_lines:
                        key_data = ''.join(key_lines)
                        key_bytes = base64.b64decode(key_data + '=' * (4 - len(key_data) % 4))
                        # Rough estimate: RSA key size ≈ length in bytes * 8 / 1024 (in bits/1024)
                        estimated_bits = len(key_bytes) * 8
                        analysis["key_size_estimate_bits"] = estimated_bits
                        analysis["key_strength"] = "Strong (2048+ bits)" if estimated_bits >= 2048 else "Weak (<2048 bits)"
            
            analysis["vulnerability"] = "RSA signature cannot be easily forged"
        
        elif algorithm == "none":
            analysis["vulnerability"] = "CRITICAL - Algorithm 'none' allows signature bypass"
        
        return analysis
    
    @staticmethod
    def compare_entropy(tokens: List[str]) -> Dict[str, any]:
        """
        Compare entropy across multiple tokens
        
        Args:
            tokens: List of JWT tokens to compare
            
        Returns:
            Comparison analysis
        """
        analyses = []
        for token in tokens:
            try:
                analysis = EntropyAnalyzer.analyze_jwt_token(token)
                analyses.append(analysis)
            except Exception as e:
                logger.error(f"Error analyzing token: {e}")
        
        if not analyses:
            return {}
        
        comparison = {
            "token_count": len(analyses),
            "average_token_length": sum(a["token_length"] for a in analyses) / len(analyses),
            "average_total_entropy": sum(a["total_entropy_bits"] for a in analyses) / len(analyses),
            "tokens": analyses
        }
        
        return comparison


def analyze_weak_secret():
    """Analyze the weak secret used in vulnerable backend"""
    weak_secret = "library-secret-123"
    
    logger.info("=" * 60)
    logger.info("ANALYZING WEAK SECRET: library-secret-123")
    logger.info("=" * 60)
    
    strength = EntropyAnalyzer.estimate_secret_strength(weak_secret)
    
    print(f"\nSecret Analysis:")
    print(f"  Length: {strength['length']} characters")
    print(f"  Entropy: {strength['entropy_bits']:.2f} bits (vs recommended 128+ bits)")
    print(f"  Charset used: {strength['charset_size']} characters")
    print(f"  Crack difficulty: {strength['crack_difficulty']}")
    print(f"  Time to crack (1B attempts/sec): {strength['crack_time_human']}")
    print(f"  Attempts needed (50%): {strength['attempts_for_50_percent']:,}")
    print(f"  Recommendation: {strength['recommendation']}")
    
    save_json_data(
        {"weak_secret_analysis": strength},
        DATA_PATHS.get("entropy_dataset", "data/entropy_analysis.json").replace(".json", "_weak_secret.json")
    )
    
    return strength


def main():
    """Run entropy analysis"""
    from attacks.hijack_library_tokens import JWTAttacker
    
    print("=" * 60)
    print("JWT ENTROPY ANALYSIS")
    print("=" * 60)
    
    # Analyze weak secret
    print("\n[1/3] Analyzing weak secret...")
    weak_analysis = analyze_weak_secret()
    
    # Analyze tokens
    print("\n[2/3] Collecting tokens for analysis...")
    attacker = JWTAttacker("vulnerable")
    valid_token = attacker.get_valid_token()
    
    if valid_token:
        print("\n[3/3] Analyzing token entropy...")
        token_analysis = EntropyAnalyzer.analyze_jwt_token(valid_token)
        print(f"\nToken Analysis:")
        print(f"  Total length: {token_analysis['token_length']} characters")
        print(f"  Total entropy: {token_analysis['total_entropy_bits']:.2f} bits")
        print(f"  Algorithm: {token_analysis['algorithm']}")
        print(f"  Signature present: {token_analysis['signature_present']}")
        
        # Save results
        results = {
            "weak_secret_analysis": weak_analysis,
            "token_analysis": token_analysis
        }
        
        save_json_data(results, DATA_PATHS.get("entropy_dataset", "data/entropy_analysis.json"))
        print(f"\nResults saved to entropy_analysis.json")
    else:
        logger.error("Could not obtain valid token for analysis")


if __name__ == "__main__":
    from core.logging_setup import initialize_all_loggers
    initialize_all_loggers()
    main()
