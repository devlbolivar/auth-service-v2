import { Schema, model, Document } from "mongoose";

// Helper interface for strongly typing instance methods
interface IUserMethods {
  isLocked(): boolean;
  incrementLoginAttempts(): Promise<void>;
  resetLoginAttempts(): Promise<void>;
}

export interface IUser extends Document {
  email: string;
  password: string;
  refreshTokens: string[];
  resetPasswordToken?: string;
  resetPasswordExpires?: Date;
  failedLoginAttempts: number;
  accountLocked: boolean;
  lockUntil?: Date;
  lastLogin?: Date;
  passwordLastChanged?: Date;
}

// Create the schema
const userSchema = new Schema(
  {
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    refreshTokens: { type: [String], default: [] },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
    failedLoginAttempts: { type: Number, default: 0 },
    accountLocked: { type: Boolean, default: false },
    lockUntil: { type: Date },
    lastLogin: { type: Date },
    passwordLastChanged: { type: Date, default: Date.now },
  },
  {
    timestamps: true, // Add createdAt and updatedAt fields
  }
);

// Add method to check if account is locked
userSchema.methods.isLocked = function (): boolean {
  // Check if the account is locked
  if (this.accountLocked && this.lockUntil) {
    // Check if the lock has expired
    return new Date() < this.lockUntil;
  }
  return false;
};

// Add method to increment failed login attempts
userSchema.methods.incrementLoginAttempts = async function (): Promise<void> {
  // If previous lock has expired, reset the attempts counter
  if (this.lockUntil && new Date() > this.lockUntil) {
    this.failedLoginAttempts = 1;
    this.accountLocked = false;
    this.lockUntil = undefined;
  } else {
    // Increment failed login attempts
    this.failedLoginAttempts += 1;

    // Lock the account if too many failed attempts (5)
    if (this.failedLoginAttempts >= 5 && !this.accountLocked) {
      this.accountLocked = true;
      // Lock for 30 minutes
      this.lockUntil = new Date(Date.now() + 30 * 60 * 1000);
    }
  }

  await this.save();
};

// Add method to reset failed login attempts
userSchema.methods.resetLoginAttempts = async function (): Promise<void> {
  this.failedLoginAttempts = 0;
  this.accountLocked = false;
  this.lockUntil = undefined;
  this.lastLogin = new Date();

  await this.save();
};

// Create and export the User model
export type UserModel = IUser & IUserMethods;
export default model<UserModel>("User", userSchema);
