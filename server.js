import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.js";
import testMailRoutes from "./routes/test-mail.js";
// import seguridadRouter from "./routes/seguridad.js";

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Ruta raíz (para comprobar que el backend está corriendo)
app.get("/", (req, res) => {
  res.send("🚀 Backend corriendo correctamente!");
});

// Rutas
app.use("/auth", authRoutes);
app.use("/test-mail", testMailRoutes);
// app.use("/api/seguridad", seguridadRouter);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});

// Servidor
app.get("/", (req, res) => {
  res.send("🚀 El backend de autenticación está funcionando.");
});

export default app;
