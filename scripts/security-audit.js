#!/usr/bin/env node
/**
 * Security Audit Script
 * This script performs security checks on the authentication service
 * configuration to ensure best practices are followed.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const dotenv = require("dotenv");

// Load environment variables
dotenv.config();

console.log("\n🔒 SECURITY AUDIT REPORT 🔒\n");

// Check if .env file exists
const envExists = fs.existsSync(path.join(process.cwd(), ".env"));
console.log(`✓ .env file exists: ${envExists ? "✅" : "❌"}`);

// Check JWT Secret
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  console.log("❌ JWT_SECRET is not set");
} else {
  const entropy = calculateEntropy(jwtSecret);
  console.log(
    `✓ JWT_SECRET entropy: ${entropy.toFixed(2)} bits ${
      entropy > 128 ? "✅" : "⚠️"
    }`
  );

  if (entropy < 128) {
    console.log(
      "   ⚠️ JWT_SECRET should have at least 128 bits of entropy for security"
    );
    console.log(
      "   💡 Consider using this command to generate a stronger secret:"
    );
    console.log(
      "      node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\""
    );
  }
}

// Check if a separate refresh token secret is used
const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;
console.log(
  `✓ Separate REFRESH_TOKEN_SECRET: ${refreshTokenSecret ? "✅" : "⚠️"}`
);

if (!refreshTokenSecret) {
  console.log(
    "   ⚠️ Using a separate secret for refresh tokens is recommended"
  );
}

// Check token expiry settings
const accessTokenExpiry = process.env.ACCESS_TOKEN_EXPIRY || "15m";
console.log(`✓ ACCESS_TOKEN_EXPIRY: ${accessTokenExpiry}`);

const refreshTokenExpiry = process.env.REFRESH_TOKEN_EXPIRY || "7d";
console.log(`✓ REFRESH_TOKEN_EXPIRY: ${refreshTokenExpiry}`);

// Check CORS configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS;
console.log(`✓ CORS ALLOWED_ORIGINS: ${allowedOrigins ? "✅" : "⚠️"}`);

if (!allowedOrigins) {
  console.log(
    "   ⚠️ ALLOWED_ORIGINS not set - CORS is configured to allow all origins"
  );
  console.log(
    "   💡 In production, specify exact origins: ALLOWED_ORIGINS=https://example.com,https://api.example.com"
  );
}

// Check Node environment
const nodeEnv = process.env.NODE_ENV;
console.log(
  `✓ NODE_ENV: ${nodeEnv || "not set"} ${
    nodeEnv === "production" ? "✅" : "⚠️"
  }`
);

// Check MongoDB URI
const mongoUri = process.env.MONGO_URI;
if (!mongoUri) {
  console.log("❌ MONGO_URI is not set");
} else {
  const isSecure =
    mongoUri.startsWith("mongodb+srv://") || mongoUri.includes("ssl=true");
  console.log(`✓ MongoDB connection security: ${isSecure ? "✅" : "⚠️"}`);

  const hasCredentials = mongoUri.includes("@");
  console.log(`✓ MongoDB authentication: ${hasCredentials ? "✅" : "⚠️"}`);

  if (!isSecure && nodeEnv === "production") {
    console.log("   ⚠️ MongoDB connection should use TLS/SSL in production");
  }

  if (!hasCredentials && nodeEnv === "production") {
    console.log(
      "   ⚠️ MongoDB connection should use authentication in production"
    );
  }
}

// Additional package checks
try {
  const packageJson = JSON.parse(
    fs.readFileSync(path.join(process.cwd(), "package.json"), "utf8")
  );

  // Check for security-related packages
  const hasHelmet = !!packageJson.dependencies.helmet;
  console.log(`✓ Helmet security headers: ${hasHelmet ? "✅" : "❌"}`);

  const hasRateLimit = !!packageJson.dependencies["express-rate-limit"];
  console.log(`✓ Rate limiting: ${hasRateLimit ? "✅" : "❌"}`);

  // Check for bcrypt (preferred for password hashing)
  const hasBcrypt = !!packageJson.dependencies.bcrypt;
  console.log(`✓ Bcrypt for password hashing: ${hasBcrypt ? "✅" : "❌"}`);
} catch (err) {
  console.log("❌ Error reading package.json");
}

console.log("\n📋 SECURITY RECOMMENDATIONS:");
console.log("1. Ensure all secrets are sufficiently random and complex");
console.log("2. Set NODE_ENV=production in production environments");
console.log("3. Use HTTPS in production");
console.log("4. Configure separate REFRESH_TOKEN_SECRET");
console.log("5. Set specific ALLOWED_ORIGINS for CORS in production");
console.log("6. Enable rate limiting for all endpoints");
console.log("7. Run npm audit regularly to check for vulnerabilities");
console.log("8. Keep dependencies updated");
console.log("9. Set secure and HttpOnly flags for cookies");

// Calculate entropy of a string
function calculateEntropy(string) {
  if (!string) return 0;

  const len = string.length;
  const frequencies = {};

  // Count character frequencies
  for (let i = 0; i < len; i++) {
    const char = string[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  // Calculate entropy
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }

  // Return total entropy in bits
  return entropy * len;
}
