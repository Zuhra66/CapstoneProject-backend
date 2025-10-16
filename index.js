// index.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
dotenv.config();

const app = express();
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(",") || "*" }));
app.use(express.json());

app.get("/health", (req, res) => res.json({ ok: true }));

// example API route
app.get("/api/hello", (req, res) => res.json({ message: "Backend up!" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API listening on port ${PORT}`));

