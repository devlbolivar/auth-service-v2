import { Router } from "express";
import { verifyToken } from "../middleware/verifytoken";

const router = Router();

router.get("/secret", verifyToken, (req, res) => {
  // This route is protected; you can access req.user here.
  res.json({ message: "This is a protected route", user: req.user });
});

export default router;
