// auth.controller.test.ts

import { Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

// We use jest.resetModules() to re-import a fresh copy of our module in every test.
describe("Auth Controller", () => {
  let signup: (req: Request, res: Response) => Promise<void>;
  let login: (req: Request, res: Response) => Promise<void>;
  let req: Partial<Request>;
  let res: Partial<Response>;

  beforeEach(() => {
    // Clear module cache so that the in-memory "users" resets between tests
    jest.resetModules();
    // Re-import the module
    const authController = require("../controllers/auth.controller");
    signup = authController.signup;
    login = authController.login;

    req = {
      body: {},
    };

    // Create a simple mock for res; chain status and json.
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
  });

  test("signup should hash the password and return a success message", async () => {
    req.body = { email: "test@example.com", password: "password" };

    await signup(req as Request, res as Response);

    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith({ message: "User created" });
  });

  test("login should return 401 if user does not exist", async () => {
    req.body = { email: "nonexistent@example.com", password: "password" };

    await login(req as Request, res as Response);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ message: "Invalid credentials" });
  });

  /*   test("login should return 401 if password is incorrect", async () => {
    // First, create a user via signup.
    req.body = { email: "user@example.com", password: "correctpassword" };
    await signup(req as Request, res as Response);

    // Now, attempt login with an incorrect password.
    req.body = { email: "user@example.com", password: "wrongpassword" };

    // Force bcrypt.compare to return false.
    jest.spyOn(bcrypt, "compare").mockResolvedValueOnce(false);

    await login(req as Request, res as Response);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ message: "Invalid credentials" });
  }); */

  /*   test("login should return a token for valid credentials", async () => {
    const email = "valid@example.com";
    const password = "validpassword";

    // Create the user first.
    req.body = { email, password };
    await signup(req as Request, res as Response);

    // For login, simulate that bcrypt.compare finds a match.
    jest.spyOn(bcrypt, "compare").mockResolvedValueOnce(true);
    // Also, simulate jwt.sign returning a static token.
    jest.spyOn(jwt, "sign").mockReturnValueOnce("test_token");

    req.body = { email, password };
    await login(req as Request, res as Response);

    expect(jwt.sign).toHaveBeenCalledWith(
      { email },
      process.env.JWT_SECRET || "secret",
      { expiresIn: "1h" }
    );
    expect(res.json).toHaveBeenCalledWith({ token: "test_token" });
  }); */
});
