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

const router = Router();

router.post("/signup", signupLimiter, signup);
router.post("/login", loginLimiter, login);
router.post("/refresh-token", refreshToken);
router.post("/logout", logout);
router.post(
  "/request-password-reset",
  passwordResetLimiter,
  requestPasswordReset
);
router.post("/reset-password", passwordResetLimiter, resetPassword);

export default router;
