# Comprehensive Test Suite Documentation

## Overview

This document describes the complete test suite for the JWT Cryptanalysis Library System project. The test suite covers all modules with comprehensive unit, integration, and security tests.

## Test Structure

```
tests/
├── conftest.py                 # Pytest fixtures and configuration
├── pytest.ini                  # Pytest configuration
├── run_tests.py               # Test runner script
├── test_utils.py              # Tests for core utilities
├── test_rsa_key_manager.py   # Tests for RSA key management
├── test_jwt_middleware.py     # Tests for JWT whitelist/blacklist
├── test_analysis.py           # Tests for analysis modules
├── test_ml_modules.py         # Tests for ML modules
└── test_integration.py        # Integration tests
```

## Test Suites

### 1. Core Utilities Tests (test_utils.py)

**Coverage:** JWT encoding/decoding, token forging, entropy calculation, file I/O

**Test Classes:**
- `TestJWTEncoding` (4 tests)
  - HS256 encoding
  - Timestamp handling
  - Multiple algorithm support

- `TestJWTDecoding` (4 tests)
  - Valid token decoding
  - Header extraction
  - Malformed token handling
  - alg:none token handling

- `TestEntropyCalculation` (4 tests)
  - Uniform distribution entropy
  - Random data entropy
  - Weak secret identification
  - Strong secret identification

- `TestJSONDataHandling` (2 tests)
  - JSON file saving
  - Directory creation

- `TestCSVHandling` (2 tests)
  - Single row CSV saving
  - Multiple row CSV saving

- `TestTokenForging` (2 tests)
  - Modified payload forging
  - Extended TTL forging

- `TestErrorHandling` (4 tests)
  - Empty token handling
  - None token handling
  - Edge cases

**Expected Result:** ✓ ALL PASS (22 tests)

### 2. RSA Key Manager Tests (test_rsa_key_manager.py)

**Coverage:** Key generation, storage, rotation, integrity verification

**Test Classes:**
- `TestRSAKeyGeneration` (4 tests)
  - 2048-bit key generation
  - 4096-bit key generation
  - Disk storage
  - Metadata creation

- `TestRSAKeyLoading` (3 tests)
  - Loading saved keys
  - Non-existent key error handling
  - Public key only loading

- `TestRSAKeyIntegrity` (2 tests)
  - Valid keypair verification
  - Corrupted keypair detection

- `TestRSAKeyRotation` (2 tests)
  - Key rotation
  - Archive and accessibility

- `TestRSAKeyStrengthReport` (2 tests)
  - Key strength report generation
  - 2048 vs 4096-bit comparison

- `TestJWTConfiguration` (5 tests)
  - Backend configuration
  - URL validation
  - Attack config existence
  - ML config existence
  - Data paths configuration

- `TestPublicKeyFormatting` (1 test)
  - JWKS format key export

**Expected Result:** ✓ ALL PASS (19 tests)

### 3. JWT Middleware Tests (test_jwt_middleware.py)

**Coverage:** Token whitelist, blacklist, anomaly detection

**Test Classes:**
- `TestJWTWhitelist` (7 tests)
  - Token addition
  - Token validation
  - Non-whitelisted rejection
  - Token revocation
  - Batch user revocation
  - Expired token cleanup
  - Statistics reporting

- `TestJWTBlacklist` (3 tests)
  - Token blacklisting
  - Non-blacklisted token allowance
  - Statistics

- `TestJWTWhitelistMiddleware` (4 tests)
  - Registration workflow
  - Validation workflow
  - Logout workflow
  - Security reporting

- `TestJWTAnomalyDetector` (10 tests)
  - Feature extraction
  - Algorithm anomaly detection (HS256)
  - alg:none detection
  - Missing claims detection
  - Unknown role detection
  - Signature anomaly detection
  - Comprehensive analysis
  - Baseline training
  - Anomaly reporting
  - Detection accuracy

- `TestAnomalyDetectionAccuracy` (2 tests)
  - Normal token not flagged
  - Malicious token flagged

**Expected Result:** ✓ ALL PASS (26 tests)

### 4. Analysis Modules Tests (test_analysis.py)

**Coverage:** Entropy analysis, brute force analysis

**Test Classes:**
- `TestEntropyAnalyzer` (10 tests)
  - Entropy calculation
  - Weak secret analysis
  - Strong secret analysis
  - Charset analysis
  - JWT token analysis
  - HS256 signature analysis
  - RS256 signature analysis
  - alg:none vulnerability detection

- `TestBruteForceAnalyzer` (9 tests)
  - Feasibility estimation
  - Wordlist attack feasibility
  - Brute force on strong secret
  - Cracking time estimation
  - Dictionary attack analysis
  - Brute force simulation
  - Various attack scenarios

- `TestTimingAttackAnalysis` (2 tests)
  - CPU attack scenario
  - GPU attack scenario

- `TestEntropyVsAttackFeasibility` (2 tests)
  - Low entropy high feasibility
  - High entropy low feasibility

- `TestCrackTimeFormatting` (2 tests)
  - Microsecond formatting
  - Year formatting

**Expected Result:** ✓ ALL PASS (25 tests)

### 5. ML Modules Tests (test_ml_modules.py)

**Coverage:** Training data collection, model training, ML pipeline

**Test Classes:**
- `TestTrainingDataCollection` (7 tests)
  - Normal token generation
  - Normal token features
  - Malicious token generation
  - Attack type labeling
  - Dataset balance
  - Dataset saving
  - Statistics

- `TestModelTraining` (6 tests)
  - Feature preparation
  - Isolation Forest training
  - Model persistence (save/load)
  - Model prediction
  - Model metadata
  - Anomaly detection capability

- `TestModelAccuracy` (2 tests)
  - Accuracy threshold
  - Precision/recall balance

- `TestFeatureSelection` (1 test)
  - Feature diversity

**Expected Result:** ✓ ALL PASS (16 tests)

### 6. Integration Tests (test_integration.py)

**Coverage:** End-to-end workflows, multi-module interactions

**Test Classes:**
- `TestEndToEndTokenValidation` (3 tests)
  - Valid token workflow
  - Suspicious token workflow
  - Complete token lifecycle

- `TestAttackDetectionIntegration` (2 tests)
  - Weak secret detection chain
  - Algorithm switching detection chain

- `TestMLPipelineIntegration` (2 tests)
  - Full ML pipeline
  - Model malicious pattern detection

- `TestSecurityLayersIntegration` (1 test)
  - Multi-layer defense

- `TestMetricsIntegration` (1 test)
  - Metrics collection

- `TestDataFlowIntegration` (1 test)
  - Token creation to validation flow

**Expected Result:** ✓ ALL PASS (10 tests)

## Running Tests

### Run All Tests
```bash
python tests/run_tests.py --all
```

### Run Unit Tests Only
```bash
python tests/run_tests.py --unit
```

### Run Integration Tests Only
```bash
python tests/run_tests.py --integration
```

### Run with Coverage Report
```bash
python tests/run_tests.py --coverage
```

### Run Specific Test File
```bash
pytest tests/test_utils.py -v
```

### Run Specific Test Class
```bash
pytest tests/test_utils.py::TestJWTEncoding -v
```

### Run Specific Test
```bash
pytest tests/test_utils.py::TestJWTEncoding::test_encode_jwt_hs256 -v
```

## Test Configuration

### pytest.ini
- **Test discovery:** `test_*.py` files
- **Output:** Verbose with short traceback
- **Test paths:** `tests/` directory

### conftest.py
Provides fixtures:
- `project_root` - Project root directory
- `vulnerable_backend` - Vulnerable backend config
- `secure_backend` - Secure backend config
- `test_credentials` - Test credentials
- `wordlist_path` - Path to wordlist
- `data_output_dir` - Data output directory
- `keys_dir` - Keys directory
- `sample_jwt_payload` - Sample JWT payload
- `sample_book_data` - Sample book data

## Test Markers

Tests are marked for selective execution:

```bash
# Run security tests only
pytest -m security tests/

# Run attack simulation tests
pytest -m attack tests/

# Run slow tests
pytest -m slow tests/

# Skip slow tests
pytest -m "not slow" tests/
```

## Expected Test Results

| Module | Unit Tests | Integration | Total |
|--------|-----------|-------------|-------|
| Utilities | 22 | 3 | 25 |
| RSA Manager | 19 | 2 | 21 |
| JWT Middleware | 26 | 3 | 29 |
| Analysis | 25 | 2 | 27 |
| ML Modules | 16 | 2 | 18 |
| **TOTAL** | **108** | **12** | **120** |

## Test Coverage Goals

- **Unit Test Coverage:** >80% of core modules
- **Integration Test Coverage:** Critical workflows
- **Security Test Coverage:** All attack vectors
- **ML Test Coverage:** Training and prediction pipeline

## Common Issues and Solutions

### Backend Not Running
Some tests require backend to be running. Skip with:
```bash
pytest -m "not requires_backend" tests/
```

### Import Errors
Ensure project root is in Python path:
```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
pytest tests/
```

### Fixture Not Found
Verify `conftest.py` is in the `tests/` directory

## CI/CD Integration

For continuous integration:

```bash
# Run all tests with coverage
pytest tests/ \
    --cov=core \
    --cov=attacks \
    --cov=analysis \
    --cov=ml_model \
    --cov-report=html \
    --cov-report=term \
    -v --tb=short
```

## Test Maintenance

### Adding New Tests
1. Create test file in `tests/` directory
2. Name following `test_*.py` pattern
3. Use `Test*` class names
4. Use `test_*` method names
5. Run locally before commit

### Updating Tests
Keep tests synchronized with code changes:
- Update test when modifying module
- Add tests for new features
- Remove outdated tests

## Performance Benchmarks

- **Unit tests:** < 30 seconds
- **Integration tests:** < 20 seconds
- **Full test suite:** < 60 seconds

## Troubleshooting

### Debug Failing Test
```bash
pytest tests/test_file.py::TestClass::test_method -vv -s
```

### Show Print Statements
```bash
pytest tests/ -s
```

### Generate HTML Report
```bash
pytest tests/ --html=report.html --self-contained-html
```

---

**Last Updated:** 2024-05-05
**Test Count:** 120 tests
**Coverage Goal:** >85%
