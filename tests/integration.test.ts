import request from "supertest";
import mongoose from "mongoose";
import { MongoMemoryServer } from "mongodb-memory-server";
import app from "../src/app";
import User from "../src/models/user.model";
import { testStore } from "../src/middleware/rateLimiter";

let mongoServer: MongoMemoryServer;

beforeAll(async () => {
  // Start an in-memory MongoDB instance
  mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();
  await mongoose.connect(uri);

  // Set JWT_SECRET environment variable for all tests
  process.env.JWT_SECRET = "test_secret_key";
  process.env.NODE_ENV = "test";
});

afterAll(async () => {
  // Close the connection and stop the in-memory server
  await mongoose.disconnect();
  await mongoServer.stop();
});

// Clear the test store and database before each test
beforeEach(async () => {
  // Clear the test store
  testStore.clear();
  // Clear all collections
  await User.deleteMany({});
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
    // First, create and login a user
    await request(app)
      .post("/api/auth/signup")
      .send({ email: "refresh@example.com", password: "mypassword" });

    const loginRes = await request(app)
      .post("/api/auth/login")
      .send({ email: "refresh@example.com", password: "mypassword" });

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
    // First, create and login a user
    await request(app)
      .post("/api/auth/signup")
      .send({ email: "logout@example.com", password: "mypassword" });

    const loginRes = await request(app)
      .post("/api/auth/login")
      .send({ email: "logout@example.com", password: "mypassword" });

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
    const signupRes = await request(app)
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
      .set("X-Forwarded-For", "192.168.1.1")
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
      .set("X-Forwarded-For", "192.168.1.2")
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
      .set("X-Forwarded-For", "192.168.1.3")
      .send({ email: testEmail });

    const resetToken = requestRes.body.resetToken;
    const newPassword = "newSecurePassword123";

    const res = await request(app)
      .post("/api/auth/reset-password")
      .set("X-Forwarded-For", "192.168.1.4")
      .send({
        resetToken,
        newPassword,
      });

    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty(
      "message",
      "Password has been reset successfully"
    );

    // Verify the new password works
    const loginRes = await request(app)
      .post("/api/auth/login")
      .set("X-Forwarded-For", "192.168.1.5")
      .send({
        email: testEmail,
        password: newPassword,
      });

    expect(loginRes.statusCode).toEqual(200);
    expect(loginRes.body).toHaveProperty("accessToken");
  });

  it("should reject password reset with invalid token", async () => {
    const res = await request(app)
      .post("/api/auth/reset-password")
      .set("X-Forwarded-For", "192.168.1.6")
      .send({
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

    const res = await request(app)
      .post("/api/auth/reset-password")
      .set("X-Forwarded-For", "192.168.1.7")
      .send({
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
    const res = await request(app)
      .post("/api/auth/reset-password")
      .set("X-Forwarded-For", "192.168.1.8")
      .send({});

    expect(res.statusCode).toEqual(400);
    expect(res.body).toHaveProperty(
      "message",
      "Reset token and new password are required"
    );
  });
});

describe("Rate Limiting Tests", () => {
  const testEmail = "ratelimit@example.com";
  const testPassword = "testPassword123";

  beforeEach(async () => {
    // Create a test user
    await request(app)
      .post("/api/auth/signup")
      .set("X-Forwarded-For", "192.168.2.1")
      .send({ email: testEmail, password: testPassword });
  });

  it("should limit password reset requests", async () => {
    // Make 3 requests (the limit) with the same IP
    for (let i = 0; i < 3; i++) {
      const res = await request(app)
        .post("/api/auth/request-password-reset")
        .set("X-Forwarded-For", "192.168.2.2")
        .send({ email: testEmail });
      expect(res.statusCode).toEqual(200);
    }

    // Fourth request should be rate limited
    const res = await request(app)
      .post("/api/auth/request-password-reset")
      .set("X-Forwarded-For", "192.168.2.2")
      .send({ email: testEmail });

    expect(res.statusCode).toEqual(429);
    expect(res.body).toHaveProperty(
      "message",
      "Too many password reset requests from this IP, please try again after 15 minutes"
    );
  });

  it("should limit login attempts", async () => {
    // Make 5 requests (the limit) with the same IP
    for (let i = 0; i < 5; i++) {
      const res = await request(app)
        .post("/api/auth/login")
        .set("X-Forwarded-For", "192.168.2.3")
        .send({ email: testEmail, password: "wrongPassword" });
      expect(res.statusCode).toEqual(401);
    }

    // Sixth request should be rate limited
    const res = await request(app)
      .post("/api/auth/login")
      .set("X-Forwarded-For", "192.168.2.3")
      .send({ email: testEmail, password: "wrongPassword" });

    expect(res.statusCode).toEqual(429);
    expect(res.body).toHaveProperty(
      "message",
      "Too many login attempts from this IP, please try again after an hour"
    );
  });

  it("should limit signup attempts", async () => {
    // Make 3 requests (the limit) with the same IP
    for (let i = 0; i < 3; i++) {
      const res = await request(app)
        .post("/api/auth/signup")
        .set("X-Forwarded-For", "192.168.2.4")
        .send({ email: `test${i}@example.com`, password: "password123" });
      expect(res.statusCode).toEqual(201);
    }

    // Fourth request should be rate limited
    const res = await request(app)
      .post("/api/auth/signup")
      .set("X-Forwarded-For", "192.168.2.4")
      .send({ email: "test4@example.com", password: "password123" });

    expect(res.statusCode).toEqual(429);
    expect(res.body).toHaveProperty(
      "message",
      "Too many signup attempts from this IP, please try again after an hour"
    );
  });

  it("should reset rate limit after window expires", async () => {
    // First, make requests up to the limit
    for (let i = 0; i < 3; i++) {
      await request(app)
        .post("/api/auth/request-password-reset")
        .set("X-Forwarded-For", "192.168.2.5")
        .send({ email: testEmail });
    }

    // Should be rate limited
    const limitedRes = await request(app)
      .post("/api/auth/request-password-reset")
      .set("X-Forwarded-For", "192.168.2.5")
      .send({ email: testEmail });
    expect(limitedRes.statusCode).toEqual(429);

    // Clear the test store to simulate time passing
    testStore.clear();

    // Should be able to make requests again
    const res = await request(app)
      .post("/api/auth/request-password-reset")
      .set("X-Forwarded-For", "192.168.2.5")
      .send({ email: testEmail });
    expect(res.statusCode).toEqual(200);
  });

  it("should handle different IPs separately", async () => {
    // Make requests from different IPs
    for (let i = 0; i < 3; i++) {
      const res = await request(app)
        .post("/api/auth/request-password-reset")
        .set("X-Forwarded-For", `192.168.2.${i + 6}`)
        .send({ email: testEmail });
      expect(res.statusCode).toEqual(200);
    }

    // Each IP should be able to make its own requests
    for (let i = 0; i < 3; i++) {
      const res = await request(app)
        .post("/api/auth/request-password-reset")
        .set("X-Forwarded-For", `192.168.2.${i + 6}`)
        .send({ email: testEmail });
      expect(res.statusCode).toEqual(200);
    }
  });
});
