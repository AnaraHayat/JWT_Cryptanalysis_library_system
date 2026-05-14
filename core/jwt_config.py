"""
JWT Configuration - Centralized settings for vulnerable and secure JWT implementations
"""

import os
from pathlib import Path

# Project root
PROJECT_ROOT = Path(__file__).parent.parent

# ==================== BACKEND CONFIGURATION ====================
BACKENDS = {
    "vulnerable": {
        "url": "http://localhost:5000",
        "port": 5000,
        "name": "Vulnerable JWT Backend",
        "jwt_secret": "library-secret-123",  # WEAK SECRET - Intentionally vulnerable
        "algorithm": "HS256",
        "description": "Library backend with vulnerable JWT (alg:none accepted, weak HMAC secret)"
    },
    "secure": {
        "url": "http://localhost:5001",
        "port": 5001,
        "name": "Hardened JWT Backend",
        "algorithm": "RS256",
        "description": "Library backend with hardened JWT (RS256 only, algorithm whitelist, ML detection)"
    }
}

# ==================== JWT CONFIGURATION ====================
JWT_CONFIG = {
    # Algorithm whitelist for secure backend
    "algorithm_whitelist": ["RS256"],
    
    # RSA configuration for secure backend
    "rsa_key_bits": 2048,
    "rsa_key_path": str(PROJECT_ROOT / "keys"),
    
    # Key rotation
    "key_rotation_days": 7,
    "grace_period_days": 30,
    
    # Token expiration
    "token_expiry_seconds": 3600,  # 1 hour
    
    # ML Anomaly Detection
    "enable_ml_detection": True,
    "ml_model_path": str(PROJECT_ROOT / "ml_model" / "jwt_detector.pkl"),
    "anomaly_threshold": 0.7,
    "anomaly_log_threshold": 0.3,  # Log suspicious activity above this
}

# ==================== ATTACK CONFIGURATION ====================
ATTACK_CONFIG = {
    # Brute-force attack
    "wordlist_path": str(PROJECT_ROOT / "secrets" / "wordlist.txt"),
    "max_brute_force_attempts": 100000,
    
    # Timing attack
    "timing_samples": 1000,
    "timing_warmup_samples": 10,
    
    # Traffic capture
    "capture_duration_seconds": 30,
    "capture_output_path": str(PROJECT_ROOT / "data" / "captured_traffic.json"),
}

# ==================== DATA CONFIGURATION ====================
DATA_PATHS = {
    "attack_results": str(PROJECT_ROOT / "data" / "attack_results.json"),
    "entropy_report": str(PROJECT_ROOT / "data" / "entropy_report.json"),
    "brute_force_stats": str(PROJECT_ROOT / "data" / "brute_force_stats.json"),
    "timing_dataset": str(PROJECT_ROOT / "data" / "jwt_timing_dataset.csv"),
    "ml_training_set": str(PROJECT_ROOT / "data" / "ml_training_set.csv"),
    "ml_model_performance": str(PROJECT_ROOT / "data" / "ml_model_performance.json"),
    "traffic_analysis": str(PROJECT_ROOT / "data" / "traffic_pattern_analysis.json"),
    "metrics_final_report": str(PROJECT_ROOT / "data" / "METRICS_FINAL_REPORT.json"),
}

# ==================== LOGGING CONFIGURATION ====================
LOG_CONFIG = {
    "log_dir": str(PROJECT_ROOT / "logs"),
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "files": {
        "jwt_issued": str(PROJECT_ROOT / "logs" / "jwt_issued.log"),
        "jwt_verified": str(PROJECT_ROOT / "logs" / "jwt_verified.log"),
        "jwt_rejected": str(PROJECT_ROOT / "logs" / "jwt_rejected.log"),
        "ml_anomalies": str(PROJECT_ROOT / "logs" / "ml_anomalies.log"),
        "demo": str(PROJECT_ROOT / "logs" / "demo.log"),
        "attacks": str(PROJECT_ROOT / "logs" / "attacks.log"),
    }
}

# ==================== FIGURE CONFIGURATION ====================
FIGURES = {
    "entropy_comparison": str(PROJECT_ROOT / "report" / "figures" / "entropy_comparison.png"),
    "brute_force_timeline": str(PROJECT_ROOT / "report" / "figures" / "brute_force_timeline.png"),
    "timing_distribution": str(PROJECT_ROOT / "report" / "figures" / "timing_distribution.png"),
    "ml_confusion_matrix": str(PROJECT_ROOT / "report" / "figures" / "ml_confusion_matrix.png"),
    "feature_importance": str(PROJECT_ROOT / "report" / "figures" / "feature_importance.png"),
    "before_after_comparison": str(PROJECT_ROOT / "report" / "figures" / "before_after_comparison.png"),
    "traffic_analysis": str(PROJECT_ROOT / "report" / "figures" / "traffic_analysis.png"),
    "algorithm_distribution": str(PROJECT_ROOT / "report" / "figures" / "algorithm_distribution.png"),
    "analysis_dashboard": str(PROJECT_ROOT / "report" / "figures" / "ANALYSIS_DASHBOARD.html"),
}

# ==================== REPORT CONFIGURATION ====================
REPORT_CONFIG = {
    "output_dir": str(PROJECT_ROOT / "report"),
    "markdown_file": str(PROJECT_ROOT / "report" / "FINAL_REPORT.md"),
    "html_file": str(PROJECT_ROOT / "report" / "FINAL_REPORT.html"),
    "pdf_file": str(PROJECT_ROOT / "report" / "FINAL_REPORT.pdf"),
    "metrics_dashboard": str(PROJECT_ROOT / "report" / "METRICS_DASHBOARD.html"),
}

# ==================== DEMO CONFIGURATION ====================
DEMO_CONFIG = {
    "output_dir": str(PROJECT_ROOT / "demo" / "demo_output"),
    "log_file": str(PROJECT_ROOT / "demo" / "demo_output" / "demo.log"),
}

# ==================== ML MODEL CONFIGURATION ====================
ML_CONFIG = {
    "model_type": "IsolationForest",
    "contamination": 0.25,  # Expected percentage of anomalies
    "random_state": 42,
    "n_estimators": 100,
    "train_test_split": 0.8,
    "features": [
        "algorithm_type",      # 0=HS256, 1=none, 2=RS256
        "payload_size",        # Size of JWT payload in bytes
        "signature_present",   # 0=no, 1=yes
        "role_claim",         # 0=user/librarian, 1=admin
        "claims_count",       # Number of claims in payload
    ]
}

# ==================== API ENDPOINTS ====================
API_ENDPOINTS = {
    "vulnerable": {
        "login_jwt": "/api/auth/login-jwt-vulnerable",
        "books_protected": "/api/books-protected",
        "members_protected": "/api/members-protected",
        "delete_book": "/api/books-protected/{id}",
        "delete_member": "/api/members-protected/{id}",
    },
    "secure": {
        "login_jwt": "/api/auth/login-jwt-secure",
        "books_protected": "/api/books-protected",
        "members_protected": "/api/members-protected",
        "delete_book": "/api/books-protected/{id}",
        "delete_member": "/api/members-protected/{id}",
    }
}

# ==================== TEST CREDENTIALS ====================
TEST_CREDENTIALS = {
    "admin": {
        "username": "admin",
        "password": "admin123",
        "role": "Admin"
    },
    "librarian": {
        "username": "librarian",
        "password": "lib123",
        "role": "Librarian"
    }
}

# ==================== HELPER FUNCTIONS ====================

def get_backend_config(backend_name):
    """Get configuration for a specific backend"""
    return BACKENDS.get(backend_name)

def get_backend_url(backend_name, endpoint_key):
    """Build full URL for a backend endpoint"""
    backend = get_backend_config(backend_name)
    endpoint = API_ENDPOINTS[backend_name][endpoint_key]
    return f"{backend['url']}{endpoint}"

def ensure_directories_exist():
    """Ensure all required directories exist"""
    dirs = [
        PROJECT_ROOT / "keys",
        PROJECT_ROOT / "logs",
        PROJECT_ROOT / "data",
        PROJECT_ROOT / "report" / "figures",
        PROJECT_ROOT / "demo" / "demo_output",
        PROJECT_ROOT / "secrets",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)

# Ensure directories on import
ensure_directories_exist()
