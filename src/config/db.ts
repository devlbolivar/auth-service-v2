// src/config/db.ts
import mongoose from "mongoose";

const connectDB = async () => {
  const mongoURI =
    process.env.MONGO_URI || "mongodb://localhost:27017/auth-service";
  try {
    await mongoose.connect(mongoURI);
    console.log("MongoDB connected");
  } catch (err) {
    console.error("Failed to connect to MongoDB:", err);
    process.exit(1);
  }
};

export default connectDB;
