// auth-vulnerable.js - Intentionally vulnerable JWT implementation
// This file demonstrates common JWT security mistakes
// DO NOT USE IN PRODUCTION - For educational purposes only

const jwt = require('jsonwebtoken');

// WEAK SECRET - Intentionally vulnerable for testing
// This secret has low entropy and can be brute-forced in seconds
const WEAK_SECRET = 'library-secret-123';

/**
 * Generate vulnerable JWT (HS256 with weak secret)
 * VULNERABILITIES:
 * - Uses weak secret (low entropy)
 * - Uses HS256 (susceptible to brute-force)
 * - No additional security measures
 */
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

/**
 * Verify vulnerable JWT - ACCEPTS ANY ALGORITHM
 * VULNERABILITIES:
 * - Accepts 'alg: none' (no signature verification)
 * - Accepts HS256 with weak secret
 * - No algorithm whitelist
 */
function verifyVulnerableJWT(token) {
  try {
    // VULNERABILITY: No algorithm validation!
    // This accepts both 'HS256' and 'none' algorithms
    const decoded = jwt.verify(token, WEAK_SECRET, { 
      algorithms: ['HS256', 'none'] 
    });
    return { valid: true, decoded };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

/**
 * Express middleware for vulnerable JWT validation
 * VULNERABILITIES:
 * - No algorithm whitelist enforcement
 * - Accepts 'alg: none' tokens
 * - Trusts unverified claims (e.g., role)
 */
function vulnerableJWTMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ 
      error: 'No token provided',
      hint: 'Include Authorization header with Bearer token'
    });
  }
  
  try {
    // VULNERABILITY: No algorithm whitelist!
    // This accepts any algorithm including 'none'
    const decoded = jwt.verify(token, WEAK_SECRET, { 
      algorithms: ['HS256', 'none'] 
    });
    req.user = decoded;
    console.log(`[JWT] Token verified | Algorithm: HS256 | User: ${decoded.username} | Role: ${decoded.role}`);
    next();
  } catch (error) {
    console.warn(`[JWT] Token verification failed | Error: ${error.message}`);
    return res.status(401).json({ 
      error: 'Invalid token',
      details: error.message 
    });
  }
}

/**
 * Debug endpoint - Returns token information
 * VULNERABILITIES:
 * - Exposes token structure
 * - Can be used to analyze patterns
 * - Should not exist in production
 */
function decodeTokenDebug(req, res) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const parts = token.split('.');
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    
    res.json({
      header,
      payload,
      signature_present: parts[2].length > 0,
      full_token: token,
      warning: 'This endpoint is for debugging only'
    });
  } catch (error) {
    res.status(400).json({ error: 'Invalid token format' });
  }
}

module.exports = {
  generateVulnerableJWT,
  verifyVulnerableJWT,
  vulnerableJWTMiddleware,
  decodeTokenDebug,
  WEAK_SECRET // Export for analysis purposes
};
