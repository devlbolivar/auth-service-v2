import { Request, Response } from "express";
import { signup, login } from "../controllers/auth.controller"; // Adjust the path if necessary

jest.setTimeout(20000);

// Global mock for bcrypt; overridden in individual tests as needed.
jest.mock("bcrypt", () => ({
  hash: jest.fn(() => Promise.resolve("hashedPassword")),
  compare: jest.fn(() => Promise.resolve(true)),
}));

describe("Auth Controller", () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let next = jest.fn();

  beforeEach(() => {
    req = { body: {} };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
  });

  test("signup should hash the password and return a success message", async () => {
    req.body = { email: "test@example.com", password: "password" };

    await signup(req as Request, res as Response);

    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ message: "User created" })
    );
  });

  test("login should return 401 if user does not exist", async () => {
    // For this test, we want bcrypt.compare to return false to simulate an invalid password.
    const bcrypt = require("bcrypt");
    bcrypt.compare.mockResolvedValueOnce(false);

    req.body = { email: "nonexistent@example.com", password: "password" };

    await login(req as Request, res as Response, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ message: "Invalid credentials" });
  });
});
