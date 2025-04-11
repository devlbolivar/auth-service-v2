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
    };
    jest.clearAllMocks();
  });

  describe("signup", () => {
    const validEmail = "test@example.com";
    const validPassword = "password123";
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
      expect(bcrypt.hash).toHaveBeenCalledWith(validPassword, 10);
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
    const validPassword = "password123";

    it("should return 401 for non-existent user", async () => {
      // Arrange
      mockRequest.body = { email: validEmail, password: validPassword };
      (User.findOne as jest.Mock).mockImplementation(() => ({
        select: () => null,
      }));

      // Act
      await login(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: "Invalid credentials",
      });
    });

    it("should return 401 for invalid password", async () => {
      // Arrange
      mockRequest.body = { email: validEmail, password: validPassword };
      (User.findOne as jest.Mock).mockImplementation(() => ({
        select: () => ({
          email: validEmail,
          password: "hashedPassword",
        }),
      }));
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      // Act
      await login(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        message: "Invalid credentials",
      });
    });
  });
});
