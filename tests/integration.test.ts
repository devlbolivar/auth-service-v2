import request from "supertest";
import mongoose from "mongoose";
import { MongoMemoryServer } from "mongodb-memory-server";
import app from "../src/app";

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
    expect(res.body).toHaveProperty("token");
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

    authToken = loginRes.body.token;
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
