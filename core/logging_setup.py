"""
Centralized logging configuration for JWT Cryptanalysis project
"""

import logging
import logging.handlers
from pathlib import Path
from core.jwt_config import LOG_CONFIG

# Create loggers dictionary
_loggers = {}

def setup_logger(name, log_file=None, level=logging.INFO):
    """
    Setup a logger with both console and file handlers
    
    Args:
        name: Logger name
        log_file: Path to log file (optional)
        level: Logging level
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_format = logging.Formatter(LOG_CONFIG["format"])
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10485760,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(level)
        file_format = logging.Formatter(LOG_CONFIG["format"])
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
    
    return logger

def get_logger(logger_type):
    """
    Get or create a logger of specific type
    
    Args:
        logger_type: Type of logger (jwt_issued, jwt_verified, jwt_rejected, ml_anomalies, demo, attacks)
        
    Returns:
        Logger instance
    """
    if logger_type not in _loggers:
        log_file = LOG_CONFIG["files"].get(logger_type)
        _loggers[logger_type] = setup_logger(logger_type, log_file)
    
    return _loggers[logger_type]

# Initialize loggers
def initialize_all_loggers():
    """Initialize all application loggers"""
    for logger_type in LOG_CONFIG["files"].keys():
        get_logger(logger_type)

# Initialize on import
initialize_all_loggers()

# Convenience functions
def log_jwt_issued(user_id, username, role, algorithm, token_hash):
    """Log JWT issuance"""
    logger = get_logger("jwt_issued")
    logger.info(f"JWT_ISSUED | UserID: {user_id} | Username: {username} | Role: {role} | Algorithm: {algorithm} | TokenHash: {token_hash[:16]}...")

def log_jwt_verified(user_id, algorithm, result, details=""):
    """Log JWT verification"""
    logger = get_logger("jwt_verified")
    logger.info(f"JWT_VERIFIED | UserID: {user_id} | Algorithm: {algorithm} | Result: {result} | {details}")

def log_jwt_rejected(reason, algorithm=None, details=""):
    """Log JWT rejection"""
    logger = get_logger("jwt_rejected")
    logger.warning(f"JWT_REJECTED | Reason: {reason} | Algorithm: {algorithm} | {details}")

def log_ml_anomaly(anomaly_score, features, action):
    """Log ML anomaly detection"""
    logger = get_logger("ml_anomalies")
    logger.warning(f"ML_ANOMALY_DETECTED | Score: {anomaly_score:.3f} | Features: {features} | Action: {action}")

def log_attack(attack_type, target, result, details=""):
    """Log attack attempt"""
    logger = get_logger("attacks")
    logger.info(f"ATTACK | Type: {attack_type} | Target: {target} | Result: {result} | {details}")

def log_demo(step, message, status="INFO"):
    """Log demo execution"""
    logger = get_logger("demo")
    if status == "ERROR":
        logger.error(f"DEMO_STEP | {step} | {message}")
    elif status == "WARNING":
        logger.warning(f"DEMO_STEP | {step} | {message}")
    else:
        logger.info(f"DEMO_STEP | {step} | {message}")
