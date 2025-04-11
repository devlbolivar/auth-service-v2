import dotenv from "dotenv";
import app from "./app";
import connectDB from "./config/db";

dotenv.config();
connectDB();

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`Auth service running on port ${PORT}`);
});
