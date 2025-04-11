import { Router } from "express";
import {
  login,
  signup,
  refreshToken,
  logout,
  requestPasswordReset,
  resetPassword,
} from "../controllers/auth.controller";

const router = Router();

router.post("/signup", signup);
router.post("/login", login);
router.post("/refresh-token", refreshToken);
router.post("/logout", logout);
router.post("/request-password-reset", requestPasswordReset);
router.post("/reset-password", resetPassword);

export default router;
