import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.js";
import testMailRoutes from "./routes/test-mail.js";
import connection from "./db.js"; // ✅ Importa la conexión a la DB

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// ✅ Ruta de salud para verificar la conexión a la DB
app.get("/health", async (req, res) => {
  try {
    connection.query('SELECT 1 + 1 AS result', (err, results) => {
      if (err) {
        console.error("❌ Health check - Error DB:", err.message);
        return res.status(500).json({ 
          status: "ERROR", 
          database: "Desconectado",
          error: err.message,
          DATABASE_URL: process.env.DATABASE_URL ? "Presente" : "Faltante",
          environment: process.env.NODE_ENV || "development"
        });
      }
      
      console.log("✅ Health check - DB Conectada");
      res.json({ 
        status: "OK", 
        database: "Conectado",
        result: results[0].result,
        environment: process.env.NODE_ENV || "development",
        timestamp: new Date().toISOString()
      });
    });
  } catch (error) {
    res.status(500).json({ 
      status: "ERROR", 
      error: error.message 
    });
  }
});

// ✅ Ruta raíz simple
app.get("/", (req, res) => {
  res.json({ 
    message: "🚀 Backend de autenticación funcionando correctamente!",
    timestamp: new Date().toISOString(),
    endpoints: {
      health: "/health",
      auth: "/auth",
      testMail: "/test-mail"
    }
  });
});

// Rutas
app.use("/auth", authRoutes);
app.use("/test-mail", testMailRoutes);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en el puerto ${PORT}`);
  console.log(`📍 Health check: http://localhost:${PORT}/health`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});

export default app;