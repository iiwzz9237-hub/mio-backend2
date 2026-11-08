
import express from "express";
import cors from "cors";
import { Server } from "socket.io";
import { createServer } from "node:http";

const app = express();
const server = createServer(app);

const FRONTEND =
  "https://mio-frontend-o4kw.onrender.com";

app.use(cors({ origin: FRONTEND }));
app.use(express.json({ limit: "16kb" }));

const io = new Server(server, {
  cors: { origin: FRONTEND }
});

// Public health check
app.get("/", (req, res) => {
  res.json({
    name: "MIO Backend",
    status: "online",
    version: "1.0.0"
  });
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

// Authentication and wallet endpoints
// will be enabled after Telegram validation
// and Supabase integration.

app.use("/api", (req, res) => {
  res.status(503).json({
    code: "SERVICE_NOT_READY"
  });
});

// Do not accept unauthenticated game clients.
io.use((socket, next) => {
  const error = new Error("Authentication required");
  error.data = { code: "AUTH_REQUIRED" };
  next(error);
});

const PORT = Number(process.env.PORT || 10000);

server.listen(PORT, "0.0.0.0", () => {
  console.log(`MIO Backend running on ${PORT}`);
});
