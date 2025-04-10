import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

// Optionally, extend the Express Request interface to include a "user" property.
// Create a file (e.g., src/types/express/index.d.ts) and add:
//   declare namespace Express {
//     export interface Request {
//       user?: any;
//     }
//   }

export const verifyToken = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Retrieve the token from the Authorization header (e.g., "Bearer <token>")
  const authHeader = req.header("Authorization");
  if (!authHeader) {
    res.status(401).json({ message: "No token provided" });
    return;
  }

  // Remove 'Bearer ' from the string if present
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.substring(7)
    : authHeader;

  try {
    // Verify the token using the secret. Ensure the secret is in your .env file.
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secret");

    // Attach the decoded user information to the request object for later use.
    req.user = decoded;

    // Proceed to the next middleware or route handler
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid token" });
  }
};
