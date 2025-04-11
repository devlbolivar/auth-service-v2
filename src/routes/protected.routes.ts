import { Router } from "express";
import {
  authenticateToken,
  csrfProtection,
} from "../middleware/auth.middleware";
import { Response } from "express";
import { AuthenticatedRequest } from "../types/custom";

const router = Router();

// Apply authentication middleware to all routes in this router
router.use(authenticateToken);

// Profile route
router.get("/profile", (req: AuthenticatedRequest, res: Response) => {
  res.json({
    message: "This is a protected route",
    user: req.user,
  });
});

// Security status endpoint - helps clients validate their security state
router.get("/security-status", (req: AuthenticatedRequest, res: Response) => {
  // Return user-specific security information
  const securityInfo = {
    userId: req.user?.userId,
    tokenExpiry: new Date((req.user?.exp || 0) * 1000).toISOString(),
    tokenType: req.user?.type,
    secureConnection:
      req.secure || req.headers["x-forwarded-proto"] === "https",
    csrfProtectionEnabled: Boolean(process.env.NODE_ENV === "production"),
    mfaEnabled: false, // Future enhancement
    passwordLastChanged: null, // Future enhancement
    lastLogin: null, // Future enhancement
    activeLoginCount: 0, // Future enhancement
  };

  res.json({
    message: "Security status",
    security: securityInfo,
    recommendedActions: [],
  });
});

// Example of a route with CSRF protection (for sensitive operations)
router.post(
  "/update-profile",
  csrfProtection,
  (req: AuthenticatedRequest, res: Response) => {
    // Process profile update with CSRF protection
    res.json({
      message: "Profile updated successfully",
      success: true,
    });
  }
);

export default router;
