import { Response, NextFunction } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import { AuthenticatedRequest } from "../types/custom";

export const authenticateToken = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  // Check token from authorization header
  const authHeader = req.headers["authorization"];
  const headerToken = authHeader && authHeader.split(" ")[1];

  // Check token from cookie (more secure option)
  const cookieToken = req.cookies?.accessToken;

  // Use token from cookie if available, otherwise use header token
  const token = cookieToken || headerToken;

  if (!token) {
    return res.status(401).json({ message: "Access token is required" });
  }

  try {
    const secret = process.env.JWT_SECRET || "test_secret_key";
    const decoded = jwt.verify(token, secret) as JwtPayload;

    // Validate that this is an access token, not a refresh token
    if (decoded.type !== "access") {
      return res.status(403).json({ message: "Invalid token type" });
    }

    if (!decoded.userId) {
      return res.status(403).json({ message: "Invalid token" });
    }

    req.user = decoded;
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return res.status(401).json({
        message: "Token expired",
        code: "TOKEN_EXPIRED",
      });
    }
    return res.status(403).json({ message: "Invalid token" });
  }
};

// CSRF protection middleware for sensitive operations
export const csrfProtection = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  const csrfToken = req.headers["x-csrf-token"];

  // In production, require CSRF token for mutating operations
  if (process.env.NODE_ENV === "production") {
    if (!csrfToken) {
      return res.status(403).json({ message: "CSRF token is required" });
    }

    // Validate CSRF token - this is a simple example;
    // In a real app, you'd validate against a token stored in the user's session
    if (
      typeof req.user?.userId !== "string" ||
      csrfToken !== `csrf-${req.user.userId}-${req.user.jti?.substring(0, 8)}`
    ) {
      return res.status(403).json({ message: "Invalid CSRF token" });
    }
  }

  next();
};
