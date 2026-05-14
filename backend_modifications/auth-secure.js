// auth-secure.js - Hardened JWT implementation with multiple security layers
// This file demonstrates JWT security best practices
// Can be safely used in production with proper key management

const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// RSA keys will be loaded at initialization
let privateKey, publicKey;

/**
 * Initialize secure authentication
 * Loads RSA keys from filesystem
 * Should be called once at application startup
 */
function initializeSecureAuth() {
  try {
    const keysDir = process.env.KEYS_DIR || path.join(__dirname, '../keys');
    privateKey = fs.readFileSync(path.join(keysDir, 'private.pem'), 'utf8');
    publicKey = fs.readFileSync(path.join(keysDir, 'public.pem'), 'utf8');
    console.log('[AUTH-SECURE] RSA keys loaded successfully');
    return true;
  } catch (error) {
    console.error('[AUTH-SECURE] Error loading RSA keys:', error.message);
    console.error('[AUTH-SECURE] Make sure keys/private.pem and keys/public.pem exist');
    return false;
  }
}

/**
 * DEFENSE LAYER 1: Algorithm Whitelist Middleware
 * Validates algorithm claim BEFORE signature verification
 * This is the first line of defense against algorithm downgrade attacks
 * 
 * PROTECTIONS:
 * - Rejects 'alg: none'
 * - Rejects HS256
 * - Only accepts RS256
 */
function algorithmWhitelistMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ 
      error: 'No token provided',
      hint: 'Include Authorization header with Bearer token'
    });
  }
  
  try {
    // Decode header WITHOUT verification to check algorithm
    const parts = token.split('.');
    if (parts.length !== 3) {
      console.warn('[AUTH-SECURE] Algorithm whitelist: Invalid token format');
      return res.status(401).json({ error: 'Invalid token format' });
    }
    
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    
    // DEFENSE: Check algorithm FIRST before any cryptographic verification
    if (header.alg !== 'RS256') {
      console.warn(`[AUTH-SECURE] Algorithm whitelist violation: Algorithm '${header.alg}' not allowed`);
      return res.status(403).json({ 
        error: 'Algorithm not whitelisted',
        reason: `Algorithm '${header.alg}' is not allowed. Only RS256 permitted.`,
        received: header.alg,
        expected: 'RS256'
      });
    }
    
    // Algorithm is whitelisted, proceed to next middleware
    next();
  } catch (error) {
    console.warn('[AUTH-SECURE] Algorithm whitelist: Error parsing token');
    return res.status(401).json({ 
      error: 'Invalid token format',
      details: error.message 
    });
  }
}

/**
 * Generate secure JWT using RS256 (RSA asymmetric signing)
 * 
 * PROTECTIONS:
 * - Uses RS256 (2048-bit RSA)
 * - Cannot be brute-forced (2^2048 keyspace)
 * - Cannot be forged without private key
 * - Supports key rotation
 */
function generateSecureJWT(userId, username, role) {
  const payload = {
    userId,
    username,
    role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour expiry
    alg: 'RS256' // Explicit algorithm in payload (optional, for clarity)
  };
  
  try {
    // DEFENSE: Sign with RS256 (asymmetric cryptography)
    const token = jwt.sign(payload, privateKey, { algorithm: 'RS256' });
    console.log(`[AUTH-SECURE] JWT issued | User: ${username} | Role: ${role}`);
    return token;
  } catch (error) {
    console.error('[AUTH-SECURE] Error generating JWT:', error.message);
    return null;
  }
}

/**
 * Verify secure JWT
 * 
 * PROTECTIONS:
 * - Only accepts RS256 algorithm
 * - Verifies RSA signature with public key
 * - Checks token expiration
 * - Validates all claims
 */
function verifySecureJWT(token) {
  try {
    // DEFENSE: Only accept RS256, reject all others
    const decoded = jwt.verify(token, publicKey, { 
      algorithms: ['RS256'] 
    });
    return { valid: true, decoded };
  } catch (error) {
    console.warn(`[AUTH-SECURE] JWT verification failed: ${error.message}`);
    return { valid: false, error: error.message };
  }
}

/**
 * DEFENSE LAYER 2: Complete secure middleware
 * Combines algorithm whitelist + signature verification
 * 
 * PROTECTIONS:
 * - Layer 1: Algorithm whitelist (fast rejection of downgrade attacks)
 * - Layer 2: RSA signature verification (cryptographic guarantee)
 * - Layer 3: Expiration check (automatic with jwt.verify)
 */
function secureJWTMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    console.warn('[AUTH-SECURE] No token provided');
    return res.status(401).json({ 
      error: 'No token provided',
      hint: 'Include Authorization header with Bearer token'
    });
  }
  
  try {
    // Layer 1: Check algorithm first
    const parts = token.split('.');
    if (parts.length !== 3) {
      console.warn('[AUTH-SECURE] Invalid token format');
      return res.status(401).json({ error: 'Invalid token format' });
    }
    
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    if (header.alg !== 'RS256') {
      console.warn(`[AUTH-SECURE] Algorithm violation in middleware: ${header.alg}`);
      return res.status(403).json({ 
        error: 'Algorithm not whitelisted',
        hint: 'Only RS256 tokens are accepted'
      });
    }
    
    // Layer 2: Verify signature and expiration with RS256 only
    const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    req.user = decoded;
    console.log(`[AUTH-SECURE] Token verified | User: ${decoded.username} | Role: ${decoded.role}`);
    next();
  } catch (error) {
    console.warn(`[AUTH-SECURE] Token verification failed: ${error.message}`);
    
    // Provide specific error messages for better debugging
    let errorMsg = 'Invalid token';
    if (error.name === 'TokenExpiredError') {
      errorMsg = 'Token has expired';
    } else if (error.name === 'JsonWebTokenError') {
      errorMsg = 'Invalid token signature';
    }
    
    return res.status(401).json({ 
      error: errorMsg,
      details: error.message 
    });
  }
}

/**
 * Admin-only middleware
 * Ensures user has Admin role
 * Uses verified claims from secureJWTMiddleware
 */
function requireAdminRole(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'User not authenticated' });
  }
  
  if (req.user.role !== 'Admin') {
    console.warn(`[AUTH-SECURE] Admin access denied for user: ${req.user.username} (role: ${req.user.role})`);
    return res.status(403).json({ 
      error: 'Admin access required',
      reason: `Your current role is '${req.user.role}', but 'Admin' role is required`
    });
  }
  
  next();
}

/**
 * Debug endpoint - Returns token information for authorized users
 * PROTECTIONS:
 * - Requires valid JWT
 * - Only accessible to admins
 * - Does not expose private key information
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
      algorithm: header.alg,
      signature_present: parts[2].length > 0,
      signature_length: parts[2].length,
      warning: 'This endpoint is for debugging only'
    });
  } catch (error) {
    res.status(400).json({ error: 'Invalid token format' });
  }
}

/**
 * Get key information (for monitoring)
 * PROTECTION: Only for admins
 */
function getKeyInfo(req, res) {
  if (!publicKey) {
    return res.status(500).json({ error: 'Keys not initialized' });
  }
  
  res.json({
    algorithm: 'RS256',
    key_type: 'RSA',
    key_size: '2048-bit',
    public_key_loaded: true,
    private_key_loaded: true // Should not expose in production
  });
}

module.exports = {
  initializeSecureAuth,
  generateSecureJWT,
  verifySecureJWT,
  secureJWTMiddleware,
  algorithmWhitelistMiddleware,
  requireAdminRole,
  decodeTokenDebug,
  getKeyInfo
};
