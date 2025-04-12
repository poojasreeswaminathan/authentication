import "./database.js";
import bcrypt from "bcrypt";
import express from "express";
import jwt from "jsonwebtoken";
import qrcode from "qrcode";
import { UserModel } from "./models.js";
export const app = express();

app.use(express.json());

app.post("/api/register", async (req, res) => {
  try{
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).send({ message: "All fields are required!" });
    }
    const existinguser=await UserModel.findOne({email});
    if(existinguser){
      return res.status(400).send({message:"Already registered this account!"});
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await UserModel.create({
      name,
      email,
      password: hashedPassword,
    });
    res.send({message:"Registration successful!"});
  }catch(error){
    console.error("Registration error", error);
    res.status(500).send({ message: "Registration failed", error });
  }
  });

app.post("/api/login", async (req, res) => {
 try{
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send({ message: "All fields are required!" });
  }
  const user =await UserModel.findOne({email});
  if (!user) {
    return res.status(400).send({ message: "Invalid email or password!" });
  }
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).send({ message: "Invalid email or password!" });
  }
  const token = jwt.sign(
    { id: user._id.toString(), email: user.email },
    process.env.JWT_SECRET,
  );
  res.send({message:"Login successful!"
  , token, user: { name: user.name, email: user.email } 
  });
}catch(error){
  console.error("Login error", error);
  res.status(500).send({ message: "Login failed please register!", error });
}
});


app.use("/api", async (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res.status(400).send({ message: "Token is required!" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded) {
      return res.status(400).send({ message: "Invalid token!" });
    }

    req.userId = decoded.userId;

    next();
  } catch (error) {
    console.error("Failed to verify token", error);
    return res.status(400).send({ message: "Invalid token!", error });
  }
});
app.get("/api/qrcode", async (req, res) => {
  try {
    if (!req.query.text) {
      return res.send({ message: "Required text!" });
    }

    const imageUrl = await qrcode.toDataURL(req.query.text, {
      scale: 15,
    });

    res.send({ imageUrl });
  } catch (error) {
    console.error("Invalid QR generation", error);
    res.send({ message: "Invalid QR generation", error });
  }
});