
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const PORT = process.env.PORT || 3000;

// ======================================
// ENVIRONMENT CONFIGURATION
// ======================================

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;

const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(",").map(origin => origin.trim())
  : "*";

// ======================================
// SUPABASE CONNECTION
// ======================================

let supabase = null;

if (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY) {
  supabase = createClient(
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY,
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    }
  );
}

// ======================================
// SECURITY & MIDDLEWARE
// ======================================

app.disable("x-powered-by");

app.use(helmet());

app.use(cors({
  origin: allowedOrigins,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "apikey"],
  credentials: false
}));

app.use(express.json({ limit: "1mb" }));

app.use(express.urlencoded({
  extended: true,
  limit: "1mb"
}));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    success: false,
    error: "Too many requests. Please try again later."
  }
});

app.use("/api", apiLimiter);

// ======================================
// BASIC ROUTES
// ======================================

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "ForLax Fashion API is running.",
    version: "1.0.0"
  });
});

// ======================================
// HEALTH CHECK
// ======================================

app.get("/api/health", async (req, res) => {
  const result = {
    success: true,
    server: "online",
    database: "not_configured",
    timestamp: new Date().toISOString()
  };

  if (!supabase) {
    return res.status(503).json({
      success: false,
      ...result,
      error: "Supabase environment variables are missing."
    });
  }

  try {
    const { error } = await supabase
      .from("delivery_settings")
      .select("id")
      .limit(1);

    if (error) {
      return res.status(503).json({
        success: false,
        ...result,
        database: "connection_error",
        error: error.message
      });
    }

    result.database = "connected";

    return res.status(200).json(result);

  } catch (error) {
    return res.status(503).json({
      success: false,
      ...result,
      database: "connection_error",
      error: "Database connection failed."
    });
  }
});

// ======================================
// 404 HANDLER
// ======================================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "API endpoint not found."
  });
});

// ======================================
// GLOBAL ERROR HANDLER
// ======================================

app.use((error, req, res, next) => {
  console.error("API Error:", error.message);

  res.status(500).json({
    success: false,
    error: "Internal server error."
  });
});

// ======================================
// START SERVER
// ======================================

app.listen(PORT, () => {
  console.log(`ForLax Fashion API running on port ${PORT}`);
});
