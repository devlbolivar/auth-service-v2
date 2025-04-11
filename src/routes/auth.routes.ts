import { Router } from "express";
import {
  login,
  signup,
  refreshToken,
  logout,
  requestPasswordReset,
  resetPassword,
} from "../controllers/auth.controller";
import {
  passwordResetLimiter,
  loginLimiter,
  signupLimiter,
} from "../middleware/rateLimiter";
import {
  validateSignup,
  validateLogin,
  validatePasswordReset,
  validateResetPassword,
} from "../middleware/validation.middleware";
import { csrfProtection } from "../middleware/auth.middleware";

const router = Router();

// Apply validation middleware before route handlers
router.post("/signup", signupLimiter, validateSignup, signup);
router.post("/login", loginLimiter, validateLogin, login);
router.post("/refresh-token", refreshToken);
router.post("/logout", csrfProtection, logout);
router.post(
  "/request-password-reset",
  passwordResetLimiter,
  validatePasswordReset,
  requestPasswordReset
);
router.post(
  "/reset-password",
  passwordResetLimiter,
  validateResetPassword,
  csrfProtection,
  resetPassword
);

export default router;
