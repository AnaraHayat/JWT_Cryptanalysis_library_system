# Backend Integration Guide

## Overview

This guide explains how to add vulnerable and secure JWT authentication to your Library Database backend.

---

## Step 1: Create Vulnerable JWT Layer

### File: `auth-vulnerable.js`

Create this file in your vulnerable Library backend directory:

```javascript
// auth-vulnerable.js - Intentionally vulnerable JWT implementation
const jwt = require('jsonwebtoken');

// WEAK SECRET - Intentionally vulnerable for testing
const WEAK_SECRET = 'library-secret-123';

// Generate vulnerable JWT (HS256 with weak secret)
function generateVulnerableJWT(userId, username, role) {
  const payload = {
    userId,
    username,
    role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour expiry
  };
  
  // Use HS256 with weak secret
  return jwt.sign(payload, WEAK_SECRET, { algorithm: 'HS256' });
}

// Verify vulnerable JWT - ACCEPTS ANY ALGORITHM (VULNERABLE!)
function verifyVulnerableJWT(token) {
  try {
    // VULNERABILITY: No algorithm validation!
    // Accepts both HS256 and 'none'
    const decoded = jwt.verify(token, WEAK_SECRET, { 
      algorithms: ['HS256', 'none'] 
    });
    return { valid: true, decoded };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

// Middleware for vulnerable JWT - ALSO ACCEPTS ANY ALGORITHM
function vulnerableJWTMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    // VULNERABILITY: No algorithm whitelist!
    const decoded = jwt.verify(token, WEAK_SECRET, { 
      algorithms: ['HS256', 'none'] 
    });
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token', details: error.message });
  }
}

module.exports = {
  generateVulnerableJWT,
  verifyVulnerableJWT,
  vulnerableJWTMiddleware,
  WEAK_SECRET
};
```

### Step 2: Add Vulnerable JWT Routes to `server.js`

Add this after your require statements and middleware setup:

```javascript
// Add this at the top with other requires
const auth = require('./auth-vulnerable.js');

// Add these routes after your existing /api/login route
// LOGIN ENDPOINT - Returns vulnerable JWT
app.post('/api/auth/login-jwt-vulnerable', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.request()
      .input('Username', sql.NVarChar, username)
      .input('Password', sql.NVarChar, password)
      .query('SELECT UserID, Role FROM Users WHERE Username=@Username AND Password=@Password');
    
    if (result.recordset.length > 0) {
      const user = result.recordset[0];
      const token = auth.generateVulnerableJWT(user.UserID, username, user.Role);
      res.json({ 
        success: true, 
        token: token,
        role: user.Role,
        message: 'Vulnerable JWT token generated'
      });
    } else {
      res.json({ success: false, message: 'Invalid credentials' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PROTECTED ENDPOINTS - Require vulnerable JWT
app.get('/api/books-protected', auth.vulnerableJWTMiddleware, async (req, res) => {
  try {
    // Optional: Log the request
    console.log(`[JWT] GET /api/books-protected by user: ${req.user.username}, role: ${req.user.role}`);
    const result = await pool.request().query('SELECT * FROM Books');
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/books-protected', auth.vulnerableJWTMiddleware, async (req, res) => {
  try {
    // Verify admin role (but this is in the JWT which can be forged!)
    if (req.user.role !== 'Admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { BookID, Title, ISBN, GenreID, AuthorID, PublisherID, YearPublished, Pages, Price } = req.body;
    await pool.request()
      .input('BookID', sql.NVarChar, BookID)
      .input('Title', sql.NVarChar, Title)
      .input('ISBN', sql.NVarChar, ISBN)
      .input('GenreID', sql.NVarChar, GenreID)
      .input('AuthorID', sql.NVarChar, AuthorID)
      .input('PublisherID', sql.NVarChar, PublisherID)
      .input('YearPublished', sql.Int, YearPublished)
      .input('Pages', sql.Int, Pages)
      .input('Price', sql.Float, Price)
      .query(`INSERT INTO Books (BookID, Title, ISBN, GenreID, AuthorID, PublisherID, YearPublished, Pages, Price) 
              VALUES (@BookID, @Title, @ISBN, @GenreID, @AuthorID, @PublisherID, @YearPublished, @Pages, @Price)`);
    res.json({ success: true, message: 'Book added successfully!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/books-protected/:id', auth.vulnerableJWTMiddleware, async (req, res) => {
  try {
    // VULNERABILITY: Trusts JWT role claim without verification!
    if (req.user.role !== 'Admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const result = await pool.request()
      .input('BookID', sql.NVarChar, req.params.id)
      .query('DELETE FROM Books WHERE BookID=@BookID');
    
    res.json({ 
      success: result.rowsAffected[0] > 0,
      message: result.rowsAffected[0] > 0 ? 'Book deleted successfully!' : 'Book not found'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Similar for members
app.get('/api/members-protected', auth.vulnerableJWTMiddleware, async (req, res) => {
  try {
    const result = await pool.request().query('SELECT * FROM Members');
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/members-protected/:id', auth.vulnerableJWTMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'Admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    const result = await pool.request()
      .input('MemberID', sql.NVarChar, req.params.id)
      .query('DELETE FROM Members WHERE MemberID=@MemberID');
    res.json({ success: result.rowsAffected[0] > 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
```

### Step 3: Change Port to 5000

In `server.js`, update the port:

```javascript
const PORT = process.env.PORT || 5000;  // Changed from 3000 to 5000
```

### Step 4: Install JWT dependency (if needed)

```bash
npm install jsonwebtoken
```

### Step 5: Start Vulnerable Backend

```bash
PORT=5000 npm start
# Or if PORT already in .env
npm start
```

**Verify it works:**
```bash
curl -X POST http://localhost:5000/api/auth/login-jwt-vulnerable \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

Should return a JWT token.

---

## Step 2: Create Secure JWT Layer

### File: `auth-secure.js`

Create this file in your secure Library backend directory:

```javascript
// auth-secure.js - Hardened JWT implementation
const jwt = require('jsonwebtoken');
const fs = require('fs');

// Load RSA keys
let privateKey, publicKey;

function initializeSecureAuth() {
  try {
    privateKey = fs.readFileSync('keys/private.pem', 'utf8');
    publicKey = fs.readFileSync('keys/public.pem', 'utf8');
  } catch (error) {
    console.error('Error loading RSA keys:', error);
  }
}

// DEFENSE LAYER 1: Algorithm Whitelist Middleware
function algorithmWhitelistMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    // Decode header WITHOUT verification to check algorithm
    const parts = token.split('.');
    if (parts.length !== 3) {
      return res.status(401).json({ error: 'Invalid token format' });
    }
    
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    
    // DEFENSE: Check algorithm FIRST before any verification
    if (header.alg !== 'RS256') {
      console.warn(`[SECURITY] Algorithm whitelist violation: ${header.alg}`);
      return res.status(403).json({ 
        error: 'Algorithm not whitelisted',
        reason: `Algorithm '${header.alg}' is not allowed. Only RS256 permitted.`,
        received: header.alg
      });
    }
    
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token format', details: error.message });
  }
}

// Generate secure JWT (RS256)
function generateSecureJWT(userId, username, role) {
  const payload = {
    userId,
    username,
    role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };
  
  // DEFENSE: Sign with RS256 (asymmetric)
  return jwt.sign(payload, privateKey, { algorithm: 'RS256' });
}

// Verify secure JWT
function verifySecureJWT(token) {
  try {
    // DEFENSE: Only accept RS256
    const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    return { valid: true, decoded };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

// DEFENSE LAYER 2: Complete secure middleware
function secureJWTMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    // Layer 1: Check algorithm
    const parts = token.split('.');
    if (parts.length !== 3) {
      return res.status(401).json({ error: 'Invalid token format' });
    }
    
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    if (header.alg !== 'RS256') {
      return res.status(403).json({ error: 'Algorithm not whitelisted' });
    }
    
    // Layer 2: Verify signature with RS256 only
    const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token', details: error.message });
  }
}

module.exports = {
  initializeSecureAuth,
  generateSecureJWT,
  verifySecureJWT,
  secureJWTMiddleware,
  algorithmWhitelistMiddleware
};
```

### Step 2a: Add Secure JWT Routes to `server.js`

Add similar routes but using secure JWT:

```javascript
// Add at top
const authSecure = require('./auth-secure.js');

// Initialize secure auth
authSecure.initializeSecureAuth();

// LOGIN ENDPOINT - Returns secure RS256 JWT
app.post('/api/auth/login-jwt-secure', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.request()
      .input('Username', sql.NVarChar, username)
      .input('Password', sql.NVarChar, password)
      .query('SELECT UserID, Role FROM Users WHERE Username=@Username AND Password=@Password');
    
    if (result.recordset.length > 0) {
      const user = result.recordset[0];
      const token = authSecure.generateSecureJWT(user.UserID, username, user.Role);
      res.json({ 
        success: true, 
        token: token,
        role: user.Role,
        message: 'Secure RS256 JWT token generated'
      });
    } else {
      res.json({ success: false, message: 'Invalid credentials' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Same endpoint structure as vulnerable, but with secureJWTMiddleware
app.get('/api/books-secure', authSecure.secureJWTMiddleware, async (req, res) => {
  try {
    const result = await pool.request().query('SELECT * FROM Books');
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/books-secure/:id', authSecure.secureJWTMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'Admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    const result = await pool.request()
      .input('BookID', sql.NVarChar, req.params.id)
      .query('DELETE FROM Books WHERE BookID=@BookID');
    res.json({ success: result.rowsAffected[0] > 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
```

### Step 2b: Change Port to 5001

```javascript
const PORT = process.env.PORT || 5001;  // Changed to 5001
```

### Step 2c: Start Secure Backend

```bash
PORT=5001 npm start
```

**Verify it works:**
```bash
curl -X POST http://localhost:5001/api/auth/login-jwt-secure \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

---

## Step 3: Generate RSA Keys

The secure backend needs RSA keys. From the Python project root:

```bash
# Create keys directory
mkdir keys

# Generate RSA keys (Python)
python -c "
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Save private key
with open('keys/private.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Save public key
with open('keys/public.pem', 'wb') as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print('RSA keys generated successfully!')
"
```

Copy the generated keys to your secure backend:

```bash
cp keys/private.pem /path/to/secure/backend/keys/
cp keys/public.pem /path/to/secure/backend/keys/
```

---

## Verification

### Test Vulnerable Backend (Port 5000)

```bash
# Get token
VULN_TOKEN=$(curl -s -X POST http://localhost:5000/api/auth/login-jwt-vulnerable \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.token')

# Test with alg:none (should work - VULNERABLE!)
# This is what the Python attack framework will do

# Test access to protected endpoint
curl -H "Authorization: Bearer $VULN_TOKEN" \
  http://localhost:5000/api/books-protected
```

### Test Secure Backend (Port 5001)

```bash
# Get token
SECURE_TOKEN=$(curl -s -X POST http://localhost:5001/api/auth/login-jwt-secure \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.token')

# Test access (should work with valid token)
curl -H "Authorization: Bearer $SECURE_TOKEN" \
  http://localhost:5001/api/books-secure

# Test with alg:none (should be rejected - PROTECTED!)
```

---

## Files Provided in `backend_modifications/`

- `auth-vulnerable.js` - Complete vulnerable JWT implementation
- `auth-secure.js` - Complete hardened JWT implementation
- `BACKEND_INTEGRATION_STEPS.md` - This guide

---

## Troubleshooting

### Module not found: jsonwebtoken
```bash
npm install jsonwebtoken
```

### Error loading RSA keys
```bash
# Make sure keys directory exists
mkdir keys
# Regenerate keys (see Step 3 above)
```

### Port already in use
```bash
# Kill process on port 5000
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Or use a different port in .env
```

### JWT verification fails
- Check that RSA keys are in `keys/` directory
- Verify `private.pem` and `public.pem` exist
- Regenerate keys if corrupted

---

## Next Steps

1. ✅ Setup both backends
2. ⏳ Run Python attack framework against vulnerable backend
3. ⏳ Verify attacks fail on secure backend
4. ⏳ Generate cryptanalysis reports
5. ⏳ Create demo and final report
