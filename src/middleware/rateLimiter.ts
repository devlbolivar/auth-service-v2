import rateLimit from "express-rate-limit";
import { Request, Response, NextFunction } from "express";

// Create a test store for rate limiting
export const testStore = new Map();

// Helper function to create rate limiter with test store
const createRateLimiter = (options: {
  windowMs: number;
  max: number;
  message: string;
}) => {
  return rateLimit({
    ...options,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => {
      const forwardedFor = req.headers["x-forwarded-for"];
      return (
        (Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor) ||
        req.ip ||
        "unknown"
      );
    },
    handler: (req: Request, res: Response) => {
      res.status(429).json({ message: options.message });
    },
    store:
      process.env.NODE_ENV === "test"
        ? {
            increment: (key: string) => {
              const current = testStore.get(key) || 0;
              testStore.set(key, current + 1);
              return Promise.resolve({
                totalHits: current + 1,
                resetTime: new Date(Date.now() + options.windowMs),
              });
            },
            decrement: (key: string) => {
              const current = testStore.get(key) || 0;
              if (current > 0) {
                testStore.set(key, current - 1);
              }
              return Promise.resolve();
            },
            resetKey: (key: string) => {
              testStore.delete(key);
              return Promise.resolve();
            },
            resetAll: () => {
              testStore.clear();
              return Promise.resolve();
            },
          }
        : undefined,
  });
};

// Rate limiter for password reset requests
export const passwordResetLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // Limit each IP to 3 requests per windowMs
  message:
    "Too many password reset requests from this IP, please try again after 15 minutes",
});

// Rate limiter for login attempts
export const loginLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Limit each IP to 5 login attempts per hour
  message:
    "Too many login attempts from this IP, please try again after an hour",
});

// Rate limiter for signup requests
export const signupLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 signup attempts per hour
  message:
    "Too many signup attempts from this IP, please try again after an hour",
});
