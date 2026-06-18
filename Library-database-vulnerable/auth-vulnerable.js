const jwt = require("jsonwebtoken");

const WEAK_SECRET = "library-secret-123";

function generateVulnerableJWT(userId, username, role) {
  const payload = {
    userId,
    username,
    role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour expiry
  };

  return jwt.sign(payload, WEAK_SECRET, { algorithm: "HS256" });
}

function verifyVulnerableJWT(token) {
  try {
    const decoded = jwt.verify(token, WEAK_SECRET, {
      algorithms: ["HS256", "none"],
    });
    return { valid: true, decoded };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

function vulnerableJWTMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      error: "No token provided",
      hint: "Include Authorization header with Bearer token",
    });
  }

  try {
    const decoded = jwt.verify(token, WEAK_SECRET, {
      algorithms: ["HS256", "none"],
    });
    req.user = decoded;
    console.log(
      `[JWT] Token verified | Algorithm: HS256 | User: ${decoded.username} | Role: ${decoded.role}`,
    );
    next();
  } catch (error) {
    console.warn(`[JWT] Token verification failed | Error: ${error.message}`);
    return res.status(401).json({
      error: "Invalid token",
      details: error.message,
    });
  }
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
      signature_present: parts[2].length > 0,
      full_token: token,
      warning: "This endpoint is for debugging only",
    });
  } catch (error) {
    res.status(400).json({ error: "Invalid token format" });
  }
}

module.exports = {
  generateVulnerableJWT,
  verifyVulnerableJWT,
  vulnerableJWTMiddleware,
  decodeTokenDebug,
  WEAK_SECRET,
};
