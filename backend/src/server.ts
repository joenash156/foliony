import express from "express";
import usersRouter from "./routes/users-routes";
import "./configs/database"; 

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json({ limit: "20mb" }))

// API routes
app.use("/user", usersRouter)


app.listen(PORT, () => {
  console.log(`The server is running on http://localhost:${PORT}`)
})