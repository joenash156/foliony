import express from "express";

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json({ limit: "20mb" }))

// API routes



app.listen(PORT, () => {
  console.log(`The server is running on http://localhost:${PORT}`)
})