const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");


let privateKey, publicKey;

function initializeSecureAuth() {
  try {
    const keysDir = process.env.KEYS_DIR || path.join(__dirname, "./keys");
    privateKey = fs.readFileSync(path.join(keysDir, "private.pem"), "utf8");
    publicKey = fs.readFileSync(path.join(keysDir, "public.pem"), "utf8");
    console.log("[AUTH-SECURE] RSA keys loaded successfully");
    return true;
  } catch (error) {
    console.error("[AUTH-SECURE] Error loading RSA keys:", error.message);
    console.error(
      "[AUTH-SECURE] Make sure keys/private.pem and keys/public.pem exist",
    );
    return false;
  }
}

function algorithmWhitelistMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      error: "No token provided",
      hint: "Include Authorization header with Bearer token",
    });
  }

  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      console.warn("[AUTH-SECURE] Algorithm whitelist: Invalid token format");
      return res.status(401).json({ error: "Invalid token format" });
    }

    const header = JSON.parse(Buffer.from(parts[0], "base64").toString());

    if (header.alg !== "RS256") {
      console.warn(
        `[AUTH-SECURE] Algorithm whitelist violation: Algorithm '${header.alg}' not allowed`,
      );
      return res.status(403).json({
        error: "Algorithm not whitelisted",
        reason: `Algorithm '${header.alg}' is not allowed. Only RS256 permitted.`,
        received: header.alg,
        expected: "RS256",
      });
    }

    next();
  } catch (error) {
    console.warn("[AUTH-SECURE] Algorithm whitelist: Error parsing token");
    return res.status(401).json({
      error: "Invalid token format",
      details: error.message,
    });
  }
}

function generateSecureJWT(userId, username, role) {
  const payload = {
    userId,
    username,
    role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    alg: "RS256",
  };

  try {
    const token = jwt.sign(payload, privateKey, { algorithm: "RS256" });
    console.log(`[AUTH-SECURE] JWT issued | User: ${username} | Role: ${role}`);
    return token;
  } catch (error) {
    console.error("[AUTH-SECURE] Error generating JWT:", error.message);
    return null;
  }
}

function verifySecureJWT(token) {
  try {
    const decoded = jwt.verify(token, publicKey, {
      algorithms: ["RS256"],
    });
    return { valid: true, decoded };
  } catch (error) {
    console.warn(`[AUTH-SECURE] JWT verification failed: ${error.message}`);
    return { valid: false, error: error.message };
  }
}

function secureJWTMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    console.warn("[AUTH-SECURE] No token provided");
    return res.status(401).json({
      error: "No token provided",
      hint: "Include Authorization header with Bearer token",
    });
  }

  try {
    const parts = token.split(".");
    if (parts.length !== 3) {
      console.warn("[AUTH-SECURE] Invalid token format");
      return res.status(401).json({ error: "Invalid token format" });
    }

    const header = JSON.parse(Buffer.from(parts[0], "base64").toString());
    if (header.alg !== "RS256") {
      console.warn(
        `[AUTH-SECURE] Algorithm violation in middleware: ${header.alg}`,
      );
      return res.status(403).json({
        error: "Algorithm not whitelisted",
        hint: "Only RS256 tokens are accepted",
      });
    }

    const decoded = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
    req.user = decoded;
    console.log(
      `[AUTH-SECURE] Token verified | User: ${decoded.username} | Role: ${decoded.role}`,
    );
    next();
  } catch (error) {
    console.warn(`[AUTH-SECURE] Token verification failed: ${error.message}`);

    let errorMsg = "Invalid token";
    if (error.name === "TokenExpiredError") {
      errorMsg = "Token has expired";
    } else if (error.name === "JsonWebTokenError") {
      errorMsg = "Invalid token signature";
    }

    return res.status(401).json({
      error: errorMsg,
      details: error.message,
    });
  }
}

function requireAdminRole(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: "User not authenticated" });
  }

  if (req.user.role !== "Admin") {
    console.warn(
      `[AUTH-SECURE] Admin access denied for user: ${req.user.username} (role: ${req.user.role})`,
    );
    return res.status(403).json({
      error: "Admin access required",
      reason: `Your current role is '${req.user.role}', but 'Admin' role is required`,
    });
  }

  next();
}

function decodeTokenDebug(req, res) {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    const parts = token.split(".");
    const header = JSON.parse(Buffer.from(parts[0], "base64").toString());
    const payload = JSON.parse(Buffer.from(parts[1], "base64").toString());

    res.json({
      header,
      payload,
      algorithm: header.alg,
      signature_present: parts[2].length > 0,
      signature_length: parts[2].length,
      warning: "This endpoint is for debugging only",
    });
  } catch (error) {
    res.status(400).json({ error: "Invalid token format" });
  }
}

function getKeyInfo(req, res) {
  if (!publicKey) {
    return res.status(500).json({ error: "Keys not initialized" });
  }

  res.json({
    algorithm: "RS256",
    key_type: "RSA",
    key_size: "2048-bit",
    public_key_loaded: true,
    private_key_loaded: true,
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
  getKeyInfo,
};
