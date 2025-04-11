import { Router } from "express";
import { authenticateToken } from "../middleware/auth.middleware";

const router = Router();

// Apply authentication middleware to all routes in this file
router.use(authenticateToken);

// Example protected route
router.get("/profile", (req, res) => {
  res.json({ message: "This is a protected route" });
});

export default router;
