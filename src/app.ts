import express from "express";
import cors from "cors";
import authRoutes from "./routes/auth.routes";
import protectedRoutes from "./routes/protected.routes";
import cookieParser from "cookie-parser";
import helmet from "helmet";

// Create the Express app
const app = express();

// Setup middlewares
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(",")
    : "*",
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"],
  maxAge: 86400, // 24 hours
};
app.use(cors(corsOptions));

// Parse cookies for token-based auth
app.use(cookieParser());

// Security headers with Helmet
app.use(helmet());

// Content-Type options
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  })
);

// Prevent MIME type sniffing
app.use(helmet.noSniff());

// Set strict transport security
if (process.env.NODE_ENV === "production") {
  app.use(
    helmet.hsts({
      maxAge: 31536000, // 1 year in seconds
      includeSubDomains: true,
      preload: true,
    })
  );
}

// Parse JSON request body with size limits
app.use(express.json({ limit: "100kb" }));

// Mount routes
app.use("/api/auth", authRoutes);
app.use("/api/protected", protectedRoutes);
// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok" });
});

// Error handling middleware
app.use(
  (
    err: Error,
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    console.error(err.stack);
    res.status(500).json({
      message: "Internal server error",
      error: process.env.NODE_ENV === "production" ? undefined : err.message,
    });
  }
);

// 404 handler for undefined routes
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

export default app;
