"""
JWT Whitelist Middleware
Maintains and enforces JWT token whitelist for enhanced security
"""

import json
import logging
from typing import Dict, List, Set, Optional
from pathlib import Path
from datetime import datetime, timedelta
import hashlib

from core.jwt_config import DATA_PATHS
from core.logging_setup import get_logger

logger = logging.getLogger(__name__)

class JWTWhitelist:
    """Manages JWT token whitelist for revocation and validation"""
    
    def __init__(self, whitelist_file: str = None):
        """
        Initialize JWT whitelist
        
        Args:
            whitelist_file: Path to whitelist storage file
        """
        if whitelist_file is None:
            whitelist_file = DATA_PATHS.get("jwt_whitelist", "data/jwt_whitelist.json")
        
        self.whitelist_file = Path(whitelist_file)
        self.whitelist_file.parent.mkdir(parents=True, exist_ok=True)
        self.whitelist: Dict[str, Dict] = {}
        self._load_whitelist()
    
    def _load_whitelist(self):
        """Load whitelist from disk"""
        try:
            if self.whitelist_file.exists():
                with open(self.whitelist_file, 'r') as f:
                    self.whitelist = json.load(f)
                logger.debug(f"Loaded {len(self.whitelist)} tokens from whitelist")
        except Exception as e:
            logger.error(f"Error loading whitelist: {e}")
            self.whitelist = {}
    
    def _save_whitelist(self):
        """Save whitelist to disk"""
        try:
            with open(self.whitelist_file, 'w') as f:
                json.dump(self.whitelist, f, indent=2)
            logger.debug(f"Saved {len(self.whitelist)} tokens to whitelist")
        except Exception as e:
            logger.error(f"Error saving whitelist: {e}")
    
    def _hash_token(self, token: str) -> str:
        """
        Hash token for storage (don't store actual tokens)
        
        Args:
            token: JWT token
            
        Returns:
            SHA-256 hash of token
        """
        return hashlib.sha256(token.encode()).hexdigest()
    
    def add_token(self, token: str, user_id: str = None, ip_address: str = None, 
                  ttl_seconds: int = 86400) -> bool:
        """
        Add token to whitelist
        
        Args:
            token: JWT token to whitelist
            user_id: Associated user ID
            ip_address: IP address where token was issued
            ttl_seconds: Time to live for whitelist entry
            
        Returns:
            True if added successfully
        """
        try:
            token_hash = self._hash_token(token)
            
            expiry = datetime.now() + timedelta(seconds=ttl_seconds)
            
            self.whitelist[token_hash] = {
                "added_at": datetime.now().isoformat(),
                "user_id": user_id,
                "ip_address": ip_address,
                "expires_at": expiry.isoformat(),
                "status": "active"
            }
            
            self._save_whitelist()
            logger.debug(f"Token added to whitelist for user {user_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error adding token to whitelist: {e}")
            return False
    
    def is_whitelisted(self, token: str) -> bool:
        """
        Check if token is in whitelist
        
        Args:
            token: JWT token to check
            
        Returns:
            True if token is valid and whitelisted
        """
        token_hash = self._hash_token(token)
        
        if token_hash not in self.whitelist:
            logger.debug("Token not found in whitelist")
            return False
        
        entry = self.whitelist[token_hash]
        
        # Check if expired
        expires_at = datetime.fromisoformat(entry["expires_at"])
        if datetime.now() > expires_at:
            logger.debug("Token has expired in whitelist")
            self.revoke_token(token)
            return False
        
        # Check status
        if entry["status"] != "active":
            logger.debug(f"Token status is not active: {entry['status']}")
            return False
        
        logger.debug(f"Token is valid and whitelisted")
        return True
    
    def revoke_token(self, token: str) -> bool:
        """
        Revoke a token from whitelist
        
        Args:
            token: JWT token to revoke
            
        Returns:
            True if revoked successfully
        """
        try:
            token_hash = self._hash_token(token)
            
            if token_hash in self.whitelist:
                self.whitelist[token_hash]["status"] = "revoked"
                self.whitelist[token_hash]["revoked_at"] = datetime.now().isoformat()
                
                self._save_whitelist()
                logger.info(f"Token revoked")
                return True
            
            logger.warning("Token not found in whitelist for revocation")
            return False
        
        except Exception as e:
            logger.error(f"Error revoking token: {e}")
            return False
    
    def revoke_user_tokens(self, user_id: str) -> int:
        """
        Revoke all tokens for a specific user
        
        Args:
            user_id: User ID whose tokens to revoke
            
        Returns:
            Number of tokens revoked
        """
        revoked_count = 0
        
        for token_hash, entry in self.whitelist.items():
            if entry.get("user_id") == user_id and entry.get("status") != "revoked":
                entry["status"] = "revoked"
                entry["revoked_at"] = datetime.now().isoformat()
                revoked_count += 1
        
        if revoked_count > 0:
            self._save_whitelist()
            logger.info(f"Revoked {revoked_count} tokens for user {user_id}")
        
        return revoked_count
    
    def cleanup_expired(self) -> int:
        """
        Remove expired tokens from whitelist
        
        Returns:
            Number of expired tokens removed
        """
        removed_count = 0
        tokens_to_remove = []
        
        for token_hash, entry in self.whitelist.items():
            expires_at = datetime.fromisoformat(entry["expires_at"])
            if datetime.now() > expires_at:
                tokens_to_remove.append(token_hash)
                removed_count += 1
        
        for token_hash in tokens_to_remove:
            del self.whitelist[token_hash]
        
        if removed_count > 0:
            self._save_whitelist()
            logger.info(f"Cleaned up {removed_count} expired tokens")
        
        return removed_count
    
    def get_statistics(self) -> Dict[str, any]:
        """
        Get whitelist statistics
        
        Returns:
            Dictionary with whitelist stats
        """
        active = sum(1 for e in self.whitelist.values() if e["status"] == "active")
        revoked = sum(1 for e in self.whitelist.values() if e["status"] == "revoked")
        expired = sum(1 for e in self.whitelist.values() 
                     if datetime.now() > datetime.fromisoformat(e["expires_at"]))
        
        unique_users = len(set(e.get("user_id") for e in self.whitelist.values() if e.get("user_id")))
        
        return {
            "total_tokens": len(self.whitelist),
            "active_tokens": active,
            "revoked_tokens": revoked,
            "expired_tokens": expired,
            "unique_users": unique_users,
            "whitelist_file": str(self.whitelist_file)
        }


class JWTBlacklist:
    """Maintains a blacklist of revoked/invalid tokens"""
    
    def __init__(self, blacklist_file: str = None):
        """
        Initialize JWT blacklist
        
        Args:
            blacklist_file: Path to blacklist storage file
        """
        if blacklist_file is None:
            blacklist_file = DATA_PATHS.get("jwt_blacklist", "data/jwt_blacklist.json")
        
        self.blacklist_file = Path(blacklist_file)
        self.blacklist_file.parent.mkdir(parents=True, exist_ok=True)
        self.blacklist: Dict[str, Dict] = {}
        self._load_blacklist()
    
    def _load_blacklist(self):
        """Load blacklist from disk"""
        try:
            if self.blacklist_file.exists():
                with open(self.blacklist_file, 'r') as f:
                    self.blacklist = json.load(f)
                logger.debug(f"Loaded {len(self.blacklist)} tokens from blacklist")
        except Exception as e:
            logger.error(f"Error loading blacklist: {e}")
            self.blacklist = {}
    
    def _save_blacklist(self):
        """Save blacklist to disk"""
        try:
            with open(self.blacklist_file, 'w') as f:
                json.dump(self.blacklist, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving blacklist: {e}")
    
    def _hash_token(self, token: str) -> str:
        """Hash token for storage"""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def add_revoked_token(self, token: str, user_id: str = None, reason: str = None) -> bool:
        """
        Add a revoked token to blacklist
        
        Args:
            token: JWT token
            user_id: Associated user ID
            reason: Reason for blacklisting
            
        Returns:
            True if added successfully
        """
        try:
            token_hash = self._hash_token(token)
            
            self.blacklist[token_hash] = {
                "added_at": datetime.now().isoformat(),
                "user_id": user_id,
                "reason": reason or "user_logout"
            }
            
            self._save_blacklist()
            logger.info(f"Token added to blacklist: {reason or 'user_logout'}")
            return True
        
        except Exception as e:
            logger.error(f"Error adding to blacklist: {e}")
            return False
    
    def is_blacklisted(self, token: str) -> bool:
        """
        Check if token is blacklisted
        
        Args:
            token: JWT token to check
            
        Returns:
            True if token is blacklisted
        """
        token_hash = self._hash_token(token)
        return token_hash in self.blacklist
    
    def get_statistics(self) -> Dict[str, any]:
        """Get blacklist statistics"""
        return {
            "total_blacklisted_tokens": len(self.blacklist),
            "blacklist_file": str(self.blacklist_file)
        }


class JWTWhitelistMiddleware:
    """Middleware for enforcing JWT whitelist checks"""
    
    def __init__(self):
        """Initialize middleware"""
        self.whitelist = JWTWhitelist()
        self.blacklist = JWTBlacklist()
    
    def validate_token(self, token: str) -> Dict[str, any]:
        """
        Validate token against whitelist/blacklist
        
        Args:
            token: JWT token to validate
            
        Returns:
            Dictionary with validation result
        """
        # Check blacklist first
        if self.blacklist.is_blacklisted(token):
            return {
                "valid": False,
                "reason": "Token is blacklisted (revoked or logged out)",
                "blacklist_check": True
            }
        
        # Check whitelist
        if not self.whitelist.is_whitelisted(token):
            return {
                "valid": False,
                "reason": "Token not in whitelist or has expired",
                "whitelist_check": True
            }
        
        return {
            "valid": True,
            "reason": "Token is valid and whitelisted"
        }
    
    def register_new_token(self, token: str, user_id: str, ip_address: str = None) -> bool:
        """
        Register a new valid token
        
        Args:
            token: JWT token
            user_id: Associated user
            ip_address: IP address of client
            
        Returns:
            True if registered successfully
        """
        return self.whitelist.add_token(token, user_id=user_id, ip_address=ip_address)
    
    def logout_token(self, token: str, user_id: str = None) -> bool:
        """
        Log out a token (blacklist it)
        
        Args:
            token: JWT token to logout
            user_id: Associated user ID
            
        Returns:
            True if logged out successfully
        """
        return self.blacklist.add_revoked_token(token, user_id=user_id, reason="user_logout")
    
    def get_security_report(self) -> Dict[str, any]:
        """
        Get security report on token management
        
        Returns:
            Dictionary with security metrics
        """
        whitelist_stats = self.whitelist.get_statistics()
        blacklist_stats = self.blacklist.get_statistics()
        
        return {
            "whitelist": whitelist_stats,
            "blacklist": blacklist_stats,
            "timestamp": datetime.now().isoformat()
        }


def main():
    """Test JWT whitelist"""
    print("=" * 60)
    print("JWT WHITELIST MIDDLEWARE TEST")
    print("=" * 60)
    
    middleware = JWTWhitelistMiddleware()
    
    # Test token
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdCJ9.signature"
    test_user = "user123"
    
    # Register token
    print("\n[1/3] Registering token...")
    registered = middleware.register_new_token(test_token, test_user, "127.0.0.1")
    print(f"  Registered: {registered}")
    
    # Validate token
    print("\n[2/3] Validating token...")
    result = middleware.validate_token(test_token)
    print(f"  Valid: {result['valid']}")
    print(f"  Reason: {result['reason']}")
    
    # Logout token
    print("\n[3/3] Logging out token...")
    logout = middleware.logout_token(test_token, test_user)
    print(f"  Logged out: {logout}")
    
    # Validate again
    result = middleware.validate_token(test_token)
    print(f"  Valid after logout: {result['valid']}")
    
    # Get report
    print("\nSecurity Report:")
    report = middleware.get_security_report()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    from core.logging_setup import initialize_all_loggers
    initialize_all_loggers()
    main()
