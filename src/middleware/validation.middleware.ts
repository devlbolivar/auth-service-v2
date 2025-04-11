import { Request, Response, NextFunction } from "express";
import { body, validationResult } from "express-validator";

// Process validation errors
export const validateRequest = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      message: "Validation error",
      errors: errors.array(),
    });
  }
  next();
};

// Validate signup request
export const validateSignup = [
  body("email")
    .isEmail()
    .withMessage("Please provide a valid email address")
    .normalizeEmail()
    .trim(),
  body("password")
    .isLength({ min: 10 })
    .withMessage("Password must be at least 10 characters long")
    .matches(/[A-Z]/)
    .withMessage("Password must contain at least one uppercase letter")
    .matches(/[a-z]/)
    .withMessage("Password must contain at least one lowercase letter")
    .matches(/[0-9]/)
    .withMessage("Password must contain at least one number")
    .matches(/[^A-Za-z0-9]/)
    .withMessage("Password must contain at least one special character")
    .trim(),
  validateRequest,
];

// Validate login request
export const validateLogin = [
  body("email")
    .isEmail()
    .withMessage("Please provide a valid email address")
    .normalizeEmail()
    .trim(),
  body("password").notEmpty().withMessage("Password is required").trim(),
  validateRequest,
];

// Validate password reset request
export const validatePasswordReset = [
  body("email")
    .isEmail()
    .withMessage("Please provide a valid email address")
    .normalizeEmail()
    .trim(),
  validateRequest,
];

// Validate reset password
export const validateResetPassword = [
  body("resetToken").notEmpty().withMessage("Reset token is required").trim(),
  body("newPassword")
    .isLength({ min: 10 })
    .withMessage("Password must be at least 10 characters long")
    .matches(/[A-Z]/)
    .withMessage("Password must contain at least one uppercase letter")
    .matches(/[a-z]/)
    .withMessage("Password must contain at least one lowercase letter")
    .matches(/[0-9]/)
    .withMessage("Password must contain at least one number")
    .matches(/[^A-Za-z0-9]/)
    .withMessage("Password must contain at least one special character")
    .trim(),
  validateRequest,
];
