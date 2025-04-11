import { Schema, model, Document } from "mongoose";

export interface IUser extends Document {
  email: string;
  password: string;
  refreshTokens: string[];
  resetPasswordToken?: string;
  resetPasswordExpires?: Date;
}

const userSchema = new Schema<IUser>({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  refreshTokens: { type: [String], default: [] },
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },
});

export default model<IUser>("User", userSchema);
