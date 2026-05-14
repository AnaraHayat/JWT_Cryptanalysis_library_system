# JWT Cryptanalysis Library System

## Project Overview

This is a comprehensive **JWT (JSON Web Token) cryptanalysis project** that demonstrates real-world authentication vulnerabilities in a Library Management System backend. The project integrates attack frameworks, cryptanalysis tools, machine learning-based detection, and protection mechanisms.

### Project Goal

**Perform cryptanalysis of JWT vulnerabilities in real-time, demonstrate exploitation techniques, design multi-layered protection mechanisms, and quantify security improvements.**

---

## Key Features

### 1. **Vulnerable JWT Implementation** (Port 5000)
- Weak HMAC-SHA256 secret: `library-secret-123`
- Accepts `alg: none` tokens (algorithm downgrade vulnerability)
- No algorithm whitelist enforcement
- No signature validation for certain cases
- Perfect for demonstrating real-world JWT flaws

### 2. **Python Attack Framework**
- **alg:none attack**: Forge tokens without signature
- **Brute-force attack**: Recover weak HMAC secret in < 2 seconds
- **Timing analysis**: Detect timing side-channels
- **Traffic capture**: Analyze JWT patterns in network traffic

### 3. **Cryptanalysis Tools**
- **Entropy analysis**: Quantify secret weakness (20 bits vs 256 bits)
- **Brute-force simulation**: Timeline of key recovery process
- **Timing analysis**: Statistical analysis of verification timing
- **Machine learning**: Anomaly detection model (Isolation Forest)
- **Differential analysis**: Compare algorithm strengths

### 4. **Hardened JWT Implementation** (Port 5001)
- RS256 (2048-bit RSA asymmetric signing)
- Algorithm whitelist: RS256 only
- Multi-layered defense-in-depth:
  1. Algorithm validation (before signature check)
  2. Cryptographic verification (RSA signature)
  3. ML-based anomaly detection (behavioral analysis)
  4. Enhanced logging & monitoring
  5. Key rotation policy

### 5. **Quantified Metrics**
- Attack success rate: 100% → 0%
- Key recovery time: feasible → infeasible
- ML detection rate: 95%+
- All improvements documented and validated

---

## Project Structure

```
jwt-cryptanalysis-library-system/
├── attacks/                  # Attack implementations
│   ├── hijack_library_tokens.py
│   ├── timing_attack_library.py
│   └── packet_capture_library.py
├── analysis/                 # Cryptanalysis tools
│   ├── jwt_entropy_analysis.py
│   ├── brute_force_analysis_library.py
│   ├── timing_analysis_library.py
│   └── generate_analysis_dashboard.py
├── ml_model/                 # ML anomaly detector
│   ├── collect_training_data.py
│   ├── train_jwt_detector.py
│   └── jwt_detector.pkl
├── core/                     # Core utilities
│   ├── jwt_config.py         # Configuration
│   ├── logging_setup.py      # Logging
│   └── utils.py              # Shared utilities
├── validation/               # Validation & metrics
│   ├── test_hardened_backend.py
│   └── collect_metrics.py
├── demo/                     # Demo & presentation
│   ├── run_comprehensive_demo.py
│   └── presentation.html
├── tests/                    # Test suite
│   ├── test_phase1_attacks.py
│   ├── test_phase2_analysis.py
│   └── test_phase3_protection.py
├── report/                   # Final report & figures
│   ├── FINAL_REPORT.md
│   ├── figures/              # Generated visualizations
│   └── METRICS_DASHBOARD.html
├── data/                     # Analysis data (auto-generated)
│   ├── attack_results.json
│   ├── entropy_report.json
│   ├── METRICS_FINAL_REPORT.json
│   └── ...
├── keys/                     # RSA keys (auto-generated)
├── logs/                     # Application logs
└── secrets/                  # Test data
    └── wordlist.txt
```

---

## Installation & Setup

### 1. Install Dependencies

```bash
# Using UV (Python package manager)
uv sync

# Or using pip
pip install -r requirements.txt
```

### 2. Setup Backends

#### Vulnerable Backend (Port 5000)

1. Copy Library-database backend to a new location:
```bash
cp -r D:\IS Project\Library-database D:\IS Project\Library-database-vulnerable
cd D:\IS Project\Library-database-vulnerable
```

2. Add JWT vulnerability layer (provided in `backend_modifications/auth-vulnerable.js`)

3. Update `server.js` to include JWT routes

4. Start on port 5000:
```bash
PORT=5000 npm start
```

#### Secure Backend (Port 5001)

1. Copy Library-database backend to another location:
```bash
cp -r D:\IS Project\Library-database D:\IS Project\Library-database-secure
cd D:\IS Project\Library-database-secure
```

2. Add secure JWT layer (provided in `backend_modifications/auth-secure.js`)

3. Update `server.js` with hardened JWT routes

4. Start on port 5001:
```bash
PORT=5001 npm start
```

### 3. Generate RSA Keys

```bash
python -m core.rsa_key_manager
# Creates keys/private.pem and keys/public.pem
```

---

## Usage

### Run Attack Demonstrations

```bash
# Basic JWT hijacking attack
python -m attacks.hijack_library_tokens

# Brute-force weak secret
python attacks/hijack_library_tokens.py brute_force

# Timing analysis
python -m attacks.timing_attack_library

# Traffic capture and analysis
python -m attacks.packet_capture_library
```

### Run Cryptanalysis

```bash
# Entropy analysis
python -m analysis.jwt_entropy_analysis

# Brute-force analysis
python -m analysis.brute_force_analysis_library

# Timing analysis
python -m analysis.timing_analysis_library

# Generate analysis dashboard
python -m analysis.generate_analysis_dashboard
```

### Train ML Model

```bash
# Collect training data
python -m ml_model.collect_training_data

# Train anomaly detector
python -m ml_model.train_jwt_detector

# Evaluate model
python -m ml_model.model_evaluation
```

### Run Validation

```bash
# Test attacks on hardened backend
python -m validation.test_hardened_backend

# Collect metrics
python -m validation.collect_metrics

# Generate metrics report
python -m validation.generate_metrics_report
```

### Run Full Demo

```bash
# Interactive demo showing vulnerability → protection
python -m demo.run_comprehensive_demo
```

### Run Tests

```bash
# Run all tests
pytest tests/

# Run specific test suite
pytest tests/test_phase1_attacks.py -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html
```

---

## Configuration

Configuration is centralized in `core/jwt_config.py`:

```python
# Backend URLs
BACKENDS = {
    "vulnerable": {"url": "http://localhost:5000", ...},
    "secure": {"url": "http://localhost:5001", ...}
}

# JWT Settings
JWT_CONFIG = {
    "algorithm_whitelist": ["RS256"],
    "rsa_key_bits": 2048,
    "anomaly_threshold": 0.7,
    ...
}

# Attack Configuration
ATTACK_CONFIG = {
    "wordlist_path": "secrets/wordlist.txt",
    "timing_samples": 1000,
    ...
}
```

---

## Key Vulnerabilities Demonstrated

### Vulnerability 1: Algorithm Downgrade (alg: none)
- **CVSS Score**: 9.8 (Critical)
- **Attack**: Craft JWT with `alg: none` (no signature)
- **Impact**: Forge tokens as any user, bypass authentication
- **Proof**: See `attacks/hijack_library_tokens.py`

### Vulnerability 2: Weak HMAC Secret
- **CVSS Score**: 9.8 (Critical)
- **Attack**: Brute-force HMAC-SHA256 with weak secret
- **Impact**: Recover secret in < 2 seconds, forge tokens
- **Proof**: See `analysis/brute_force_analysis_library.py`

### Vulnerability 3: Missing Algorithm Whitelist
- **CVSS Score**: 9.1 (Critical)
- **Attack**: Send token with non-approved algorithm
- **Impact**: Algorithm confusion attacks
- **Proof**: Multiple attack vectors in framework

---

## Protection Mechanisms

### Layer 1: Algorithm Whitelist
- Validates algorithm BEFORE signature verification
- Only accepts RS256
- Rejects alg:none with 403 Forbidden

### Layer 2: RSA Asymmetric Signing
- 2048-bit RSA keypair
- Signature verification with public key
- Brute-force infeasible (2^2048 keyspace)

### Layer 3: ML Anomaly Detection
- Isolation Forest model
- Features: algorithm, payload_size, role_claim, etc.
- 95% detection rate on known attacks

### Layer 4: Enhanced Logging
- Every JWT event logged
- Enables forensic investigation
- Multi-layer logging (issued, verified, rejected, anomalies)

### Layer 5: Key Rotation
- Automatic rotation every 7 days
- 30-day grace period for clients
- Limits compromise impact

---

## Results & Metrics

### Before (Vulnerable Implementation)
- ✗ alg:none attack success: **100%**
- ✗ Brute-force success: **100%** (~1.2 seconds)
- ✗ Unauthorized admin actions: **Possible**
- ✗ Key recovery time: **< 2 seconds**

### After (Hardened Implementation)
- ✓ alg:none attack success: **0%** (Rejected by whitelist)
- ✓ Brute-force success: **0%** (RSA key infeasible)
- ✓ Unauthorized admin actions: **Blocked**
- ✓ Key recovery time: **∞ (Impossible)**
- ✓ ML detection rate: **95%+**
- ✓ ML false positive: **< 3%**

---

## Evaluation Alignment

This project meets **Complex Engineering Problem (CEP)** criteria:

| Criterion | Implementation |
|-----------|-----------------|
| **WP1: Depth of Knowledge** | Deep JWT understanding, cryptography, real-world systems |
| **WP3: In-Depth Analysis** | 6+ analytical methods with quantified findings |
| **WP4: Infrequent Issues** | Multi-layered defense-in-depth, ML-based protection |
| **Demo (25%)** | Live attack → defense demonstration |
| **Report (20%)** | Comprehensive documentation with all findings |

---

## Documentation

- **VULNERABILITY_ANALYSIS.md**: Deep dive into JWT vulnerabilities
- **PHASE1_FINDINGS.md**: Attack demonstration results
- **PHASE2_ANALYSIS.md**: Cryptanalysis findings
- **PHASE3_PROTECTION.md**: Protection mechanism design
- **PHASE4_VALIDATION.md**: Validation results
- **FINAL_REPORT.md**: Comprehensive final report

---

## Troubleshooting

### Backend Connection Error
```bash
# Check if backends are running
curl http://localhost:5000/api/books
curl http://localhost:5001/api/books

# Check logs
tail -f logs/*.log
```

### JWT Validation Errors
```bash
# Verify RSA keys exist
ls -la keys/
# Regenerate if needed
python -m core.rsa_key_manager
```

### ML Model Issues
```bash
# Retrain model
python -m ml_model.train_jwt_detector

# Verify model exists
ls -la ml_model/jwt_detector.pkl
```
