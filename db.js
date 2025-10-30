// db.js - Versión mejorada con pooling
import mysql from "mysql2";
import dotenv from "dotenv";

dotenv.config();

const pool = mysql.createPool({
  uri: process.env.DATABASE_URL,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
  ssl: { rejectUnauthorized: false } // ⚠️ IMPORTANTE para Railway
});

// Verificar conexión
pool.getConnection((err, connection) => {
  if (err) {
    console.error("❌ Error conectando a Railway:", err);
  } else {
    console.log("✅ Conectado a MySQL en Railway via pool");
    connection.release();
  }
});

export default pool;