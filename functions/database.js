import dotenv from "dotenv";
import mongoose from "mongoose";

dotenv.config();

if (process.env.MONGO_URI) {
  mongoose
    .connect(process.env.MONGO_URI)
    .then(() => {
      console.log("Successfully connected to mongodb!");
    })
    .catch((error) => {
      console.error("Failed to connect to mongodb!", error);
    });
} else {
  console.warn("MONGO_URI is not set!");
}
