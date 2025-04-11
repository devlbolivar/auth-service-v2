import request from "supertest";
import mongoose from "mongoose";
import { MongoMemoryServer } from "mongodb-memory-server";
import app from "../src/app";
import User from "../src/models/user.model";

let mongoServer: MongoMemoryServer;

beforeAll(async () => {
  // Start an in-memory MongoDB instance
  mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();
  await mongoose.connect(uri);

  // Set JWT_SECRET environment variable for all tests
  process.env.JWT_SECRET = "test_secret_key";
});

afterAll(async () => {
  // Close the connection and stop the in-memory server
  await mongoose.disconnect();
  await mongoServer.stop();
});

describe("Auth API Integration Tests", () => {
  it("should sign up a new user", async () => {
    const res = await request(app)
      .post("/api/auth/signup")
      .send({ email: "test@example.com", password: "password123" });

    expect(res.statusCode).toEqual(201);
    expect(res.body).toHaveProperty("message", "User created");
    expect(res.body).toHaveProperty("userId");
  });

  it("should login with correct credentials", async () => {
    // First, sign up the user
    await request(app)
      .post("/api/auth/signup")
      .send({ email: "login@example.com", password: "mypassword" });

    const res = await request(app)
      .post("/api/auth/login")
      .send({ email: "login@example.com", password: "mypassword" });

    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty("accessToken");
    expect(res.body).toHaveProperty("refreshToken");
    expect(res.body).toHaveProperty("userId");
  });

  it("should refresh access token with valid refresh token", async () => {
    // First, login to get tokens
    const loginRes = await request(app)
      .post("/api/auth/login")
      .send({ email: "login@example.com", password: "mypassword" });

    const { refreshToken } = loginRes.body;

    // Use refresh token to get new access token
    const refreshRes = await request(app)
      .post("/api/auth/refresh-token")
      .send({ refreshToken });

    expect(refreshRes.statusCode).toEqual(200);
    expect(refreshRes.body).toHaveProperty("accessToken");
  });

  it("should reject invalid refresh token", async () => {
    const res = await request(app)
      .post("/api/auth/refresh-token")
      .send({ refreshToken: "invalid-token" });

    expect(res.statusCode).toEqual(403);
  });

  it("should logout and invalidate refresh token", async () => {
    // First, login to get tokens
    const loginRes = await request(app)
      .post("/api/auth/login")
      .send({ email: "login@example.com", password: "mypassword" });

    const { refreshToken } = loginRes.body;

    // Logout
    const logoutRes = await request(app)
      .post("/api/auth/logout")
      .send({ refreshToken });

    expect(logoutRes.statusCode).toEqual(200);

    // Try to use the logged out refresh token
    const refreshRes = await request(app)
      .post("/api/auth/refresh-token")
      .send({ refreshToken });

    expect(refreshRes.statusCode).toEqual(403);
  });
});

describe("Protected Routes Integration Tests", () => {
  let authToken: string;

  beforeEach(async () => {
    // Create a user and get token for protected route tests
    await request(app)
      .post("/api/auth/signup")
      .send({ email: "protected@example.com", password: "securepass" });

    const loginRes = await request(app)
      .post("/api/auth/login")
      .send({ email: "protected@example.com", password: "securepass" });

    authToken = loginRes.body.accessToken;
  });

  it("should access protected route with valid token", async () => {
    const res = await request(app)
      .get("/api/protected/profile")
      .set("Authorization", `Bearer ${authToken}`);

    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty("message", "This is a protected route");
  });

  it("should reject access to protected route without token", async () => {
    const res = await request(app).get("/api/protected/profile");

    expect(res.statusCode).toEqual(401);
  });
});

describe("Password Reset Integration Tests", () => {
  const testEmail = "reset@example.com";
  const testPassword = "originalPassword";
  let resetToken: string;

  beforeEach(async () => {
    // Create a test user
    await request(app)
      .post("/api/auth/signup")
      .send({ email: testEmail, password: testPassword });
  });

  it("should request password reset for existing user", async () => {
    const res = await request(app)
      .post("/api/auth/request-password-reset")
      .send({ email: testEmail });

    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty(
      "message",
      "Password reset link has been sent to your email"
    );
    expect(res.body).toHaveProperty("resetToken");

    // Store the reset token for the next test
    resetToken = res.body.resetToken;
  });

  it("should request password reset for non-existent user", async () => {
    const res = await request(app)
      .post("/api/auth/request-password-reset")
      .send({ email: "nonexistent@example.com" });

    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty(
      "message",
      "If your email is registered, you will receive a password reset link"
    );
  });

  it("should reset password with valid token", async () => {
    // First, get a reset token
    const requestRes = await request(app)
      .post("/api/auth/request-password-reset")
      .send({ email: testEmail });

    const resetToken = requestRes.body.resetToken;
    const newPassword = "newSecurePassword123";

    const res = await request(app).post("/api/auth/reset-password").send({
      resetToken,
      newPassword,
    });

    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty(
      "message",
      "Password has been reset successfully"
    );

    // Verify the new password works
    const loginRes = await request(app).post("/api/auth/login").send({
      email: testEmail,
      password: newPassword,
    });

    expect(loginRes.statusCode).toEqual(200);
    expect(loginRes.body).toHaveProperty("accessToken");
  });

  it("should reject password reset with invalid token", async () => {
    const res = await request(app).post("/api/auth/reset-password").send({
      resetToken: "invalid-token",
      newPassword: "newPassword123",
    });

    expect(res.statusCode).toEqual(400);
    expect(res.body).toHaveProperty(
      "message",
      "Invalid or expired reset token"
    );
  });

  it("should reject password reset with expired token", async () => {
    // Create a user and set an expired reset token
    const user = await User.findOne({ email: testEmail });
    if (user) {
      user.resetPasswordToken = "expired-token";
      user.resetPasswordExpires = new Date(Date.now() - 3600000); // 1 hour ago
      await user.save();
    }

    const res = await request(app).post("/api/auth/reset-password").send({
      resetToken: "expired-token",
      newPassword: "newPassword123",
    });

    expect(res.statusCode).toEqual(400);
    expect(res.body).toHaveProperty(
      "message",
      "Invalid or expired reset token"
    );
  });

  it("should reject password reset without required fields", async () => {
    const res = await request(app).post("/api/auth/reset-password").send({});

    expect(res.statusCode).toEqual(400);
    expect(res.body).toHaveProperty(
      "message",
      "Reset token and new password are required"
    );
  });
});
