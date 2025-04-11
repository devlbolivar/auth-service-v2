import { Request, Response } from "express";
import bcrypt from "bcrypt";
import { signup, login } from "../controllers/auth.controller";
import User from "../models/user.model";

jest.mock("bcrypt");
jest.mock("../models/user.model");

describe("Auth Controller", () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  const mockNext = jest.fn();

  beforeEach(() => {
    mockRequest = {
      body: {},
    };
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
      cookie: jest.fn(),
    };
    jest.clearAllMocks();
  });

  describe("signup", () => {
    const validEmail = "test@example.com";
    const validPassword = "Password123!";
    const hashedPassword = "hashedPassword";

    beforeEach(() => {
      (bcrypt.hash as jest.Mock).mockResolvedValue(hashedPassword);
    });

    it("should create a new user successfully", async () => {
      // Arrange
      mockRequest.body = { email: validEmail, password: validPassword };
      (User.findOne as jest.Mock).mockResolvedValue(null);
      (User.create as jest.Mock).mockResolvedValue({
        _id: "mockUserId",
        email: validEmail,
        password: hashedPassword,
      });

      // Act
      await signup(mockRequest as Request, mockResponse as Response);

      // Assert
      expect(User.findOne).toHaveBeenCalledWith({ email: validEmail });
      expect(bcrypt.hash).toHaveBeenCalledWith(validPassword, 12);
      expect(User.create).toHaveBeenCalledWith({
        email: validEmail,
        password: hashedPassword,
      });
      expect(mockResponse.status).toHaveBeenCalledWith(201);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: "User created",
        userId: "mockUserId",
      });
    });

    it("should return 400 if email or password is missing", async () => {
      // Arrange
      mockRequest.body = {};

      // Act
      await signup(mockRequest as Request, mockResponse as Response);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: "Email and password are required",
      });
    });

    it("should return 400 if email format is invalid", async () => {
      // Arrange
      mockRequest.body = { email: "invalid-email", password: validPassword };

      // Act
      await signup(mockRequest as Request, mockResponse as Response);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: "Invalid email format",
      });
    });

    it("should return 400 if password does not meet complexity requirements", async () => {
      // Arrange
      mockRequest.body = { email: validEmail, password: "simple" };

      // Act
      await signup(mockRequest as Request, mockResponse as Response);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: "Password must be at least 10 characters long",
      });
    });

    it("should return 400 if user already exists", async () => {
      // Arrange
      mockRequest.body = { email: validEmail, password: validPassword };
      (User.findOne as jest.Mock).mockResolvedValue({ email: validEmail });

      // Act
      await signup(mockRequest as Request, mockResponse as Response);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: "User already exists",
      });
    });
  });

  describe("login", () => {
    const validEmail = "test@example.com";
    const validPassword = "Password123!";

    beforeEach(() => {
      // Mock the user model's methods for account lockout
      const mockUser = {
        _id: "mockUserId",
        email: validEmail,
        password: "hashedPassword",
        isLocked: jest.fn().mockReturnValue(false),
        incrementLoginAttempts: jest.fn().mockResolvedValue(undefined),
        resetLoginAttempts: jest.fn().mockResolvedValue(undefined),
        failedLoginAttempts: 0,
        accountLocked: false,
        refreshTokens: [],
        save: jest.fn().mockResolvedValue(undefined),
      };

      (User.findOne as jest.Mock).mockImplementation(() => ({
        select: () => mockUser,
      }));
    });

    it("should return 401 for non-existent user", async () => {
      // Arrange
      mockRequest.body = { email: validEmail, password: validPassword };
      (User.findOne as jest.Mock).mockImplementation(() => ({
        select: () => null,
      }));

      // Mock bcrypt.hash for timing attack prevention
      (bcrypt.hash as jest.Mock).mockResolvedValue("dummy-hash");

      // Act
      await login(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(bcrypt.hash).toHaveBeenCalledWith("dummy-password", 12);
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: "Invalid credentials",
      });
    });

    it("should return 401 for invalid password", async () => {
      // Arrange
      mockRequest.body = { email: validEmail, password: validPassword };
      const mockUser = {
        _id: "mockUserId",
        email: validEmail,
        password: "hashedPassword",
        isLocked: jest.fn().mockReturnValue(false),
        incrementLoginAttempts: jest.fn().mockResolvedValue(undefined),
        resetLoginAttempts: jest.fn().mockResolvedValue(undefined),
        failedLoginAttempts: 1,
        accountLocked: false,
        refreshTokens: [],
        save: jest.fn().mockResolvedValue(undefined),
      };

      (User.findOne as jest.Mock).mockImplementation(() => ({
        select: () => mockUser,
      }));

      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      // Act
      await login(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockUser.incrementLoginAttempts).toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: "Invalid credentials",
        attemptsRemaining: 4,
      });
    });

    it("should return 423 for locked account", async () => {
      // Arrange
      mockRequest.body = { email: validEmail, password: validPassword };
      const mockUser = {
        _id: "mockUserId",
        email: validEmail,
        password: "hashedPassword",
        isLocked: jest.fn().mockReturnValue(true),
        incrementLoginAttempts: jest.fn().mockResolvedValue(undefined),
        resetLoginAttempts: jest.fn().mockResolvedValue(undefined),
        lockUntil: new Date(Date.now() + 1000 * 60 * 30), // 30 minutes in the future
        accountLocked: true,
        refreshTokens: [],
        save: jest.fn().mockResolvedValue(undefined),
      };

      (User.findOne as jest.Mock).mockImplementation(() => ({
        select: () => mockUser,
      }));

      // Act
      await login(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockUser.isLocked).toHaveBeenCalled();
      expect(mockResponse.status).toHaveBeenCalledWith(423);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: "Account is locked due to too many failed login attempts",
        lockExpires: mockUser.lockUntil,
      });
    });
  });
});
