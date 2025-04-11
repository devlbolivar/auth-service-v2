import express from "express";
import cors from "cors";
import authRoutes from "./routes/auth.routes";
import connectDB from "./config/db";

// Create the Express app
const app = express();

// Setup middlewares
app.use(cors());
app.use(express.json());

// Mount routes
app.use("/api/auth", authRoutes);

export default app;
