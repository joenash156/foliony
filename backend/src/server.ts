import express from "express";
import usersRouter from "./routes/users-routes";
import "./configs/database"; 
import cookieParser from "cookie-parser";

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json({ limit: "20mb" }))
app.use(cookieParser());

// API routes
app.use("/user", usersRouter)


app.listen(PORT, () => {
  console.log(`The server is running on http://localhost:${PORT}`)
})