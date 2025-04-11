import { Request, Response, RequestHandler } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import User, { IUser } from "../models/user.model";

// Remove unused variable
export const signup = async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;

  // Add input validation
  if (!email || !password) {
    res.status(400).json({ message: "Email and password are required" });
    return;
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      res.status(400).json({ message: "User already exists" });
      return;
    }

    const saltRounds = 10;
    const hashed = await bcrypt.hash(password, saltRounds);
    const user: IUser = await User.create({ email, password: hashed });

    res.status(201).json({
      message: "User created",
      userId: user._id,
    });
  } catch (error) {
    // Log error for debugging
    console.error("Signup error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const login: RequestHandler = async (req, res): Promise<void> => {
  const { email, password } = req.body;

  // Add input validation
  if (!email || !password) {
    res.status(400).json({ message: "Email and password are required" });
    return;
  }

  try {
    const user = await User.findOne({ email }).select("+password");
    if (!user) {
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    if (!process.env.JWT_SECRET) {
      throw new Error("JWT_SECRET is not defined");
    }

    // Generate access token
    const accessToken = jwt.sign(
      {
        userId: user._id,
        email: user.email,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    // Generate refresh token
    const refreshToken = jwt.sign(
      {
        userId: user._id,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    // Store refresh token in user document
    user.refreshTokens.push(refreshToken);
    await user.save();

    res.json({
      message: "Login successful",
      accessToken,
      refreshToken,
      userId: user._id,
    });
  } catch (error) {
    // Log error for debugging
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const refreshToken: RequestHandler = async (req, res): Promise<void> => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    res.status(400).json({ message: "Refresh token is required" });
    return;
  }

  try {
    if (!process.env.JWT_SECRET) {
      throw new Error("JWT_SECRET is not defined");
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET) as {
      userId: string;
    };
    const user = await User.findById(decoded.userId);

    if (!user || !user.refreshTokens.includes(refreshToken)) {
      res.status(403).json({ message: "Invalid refresh token" });
      return;
    }

    // Generate new access token
    const accessToken = jwt.sign(
      {
        userId: user._id,
        email: user.email,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    res.json({
      message: "Token refreshed successfully",
      accessToken,
    });
  } catch (error) {
    console.error("Refresh token error:", error);
    res.status(403).json({ message: "Invalid refresh token" });
  }
};

export const logout: RequestHandler = async (req, res): Promise<void> => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    res.status(400).json({ message: "Refresh token is required" });
    return;
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET || "") as {
      userId: string;
    };
    const user = await User.findById(decoded.userId);

    if (user) {
      // Remove the refresh token from the user's list
      user.refreshTokens = user.refreshTokens.filter(
        (token) => token !== refreshToken
      );
      await user.save();
    }

    res.json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const requestPasswordReset: RequestHandler = async (
  req,
  res
): Promise<void> => {
  const { email } = req.body;

  if (!email) {
    res.status(400).json({ message: "Email is required" });
    return;
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      // For security reasons, we don't reveal if the email exists
      res.status(200).json({
        message:
          "If your email is registered, you will receive a password reset link",
      });
      return;
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour from now

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = resetTokenExpiry;
    await user.save();

    // In a real application, you would send an email here with the reset token
    // For now, we'll just return the token (in production, this should be removed)
    res.status(200).json({
      message: "Password reset link has been sent to your email",
      resetToken, // Remove this in production
    });
  } catch (error) {
    console.error("Password reset request error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

export const resetPassword: RequestHandler = async (
  req,
  res
): Promise<void> => {
  const { resetToken, newPassword } = req.body;

  if (!resetToken || !newPassword) {
    res
      .status(400)
      .json({ message: "Reset token and new password are required" });
    return;
  }

  try {
    const user = await User.findOne({
      resetPasswordToken: resetToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      res.status(400).json({ message: "Invalid or expired reset token" });
      return;
    }

    // Hash new password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update password and clear reset token
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: "Password has been reset successfully" });
  } catch (error) {
    console.error("Password reset error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};
