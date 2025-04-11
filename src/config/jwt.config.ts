import crypto from "crypto";

// Interface for JWT configuration
interface JWTConfig {
  accessToken: {
    secret: string;
    expiresIn: string;
    algorithm: string;
  };
  refreshToken: {
    secret: string;
    expiresIn: string;
    algorithm: string;
  };
  cookieOptions: {
    httpOnly: boolean;
    secure: boolean;
    sameSite: "strict" | "lax" | "none";
  };
}

// Get the JWT secret from environment variables or generate a strong one
export const getJwtSecret = (): string => {
  // In production, require a set JWT_SECRET
  if (process.env.NODE_ENV === "production" && !process.env.JWT_SECRET) {
    console.error("JWT_SECRET environment variable is required in production!");
    process.exit(1);
  }

  // Use the environment variable if set, otherwise use a secure default for development/test
  return process.env.JWT_SECRET || "test_secret_key";
};

// Get the refresh token secret - ideally different from the access token secret
export const getRefreshTokenSecret = (): string => {
  // In production, prefer a separate refresh token secret
  if (process.env.REFRESH_TOKEN_SECRET) {
    return process.env.REFRESH_TOKEN_SECRET;
  }

  // Fall back to JWT_SECRET if refresh secret not available
  return getJwtSecret();
};

// Generate a unique token ID for tracking
export const generateTokenId = (): string => {
  return crypto.randomBytes(16).toString("hex");
};

// JWT configuration
export const jwtConfig: JWTConfig = {
  accessToken: {
    secret: getJwtSecret(),
    expiresIn: process.env.ACCESS_TOKEN_EXPIRY || "15m",
    algorithm: "HS256",
  },
  refreshToken: {
    secret: getRefreshTokenSecret(),
    expiresIn: process.env.REFRESH_TOKEN_EXPIRY || "7d",
    algorithm: "HS256",
  },
  cookieOptions: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  },
};

export default jwtConfig;
