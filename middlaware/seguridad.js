// ===== LIBRERÍAS =====
import jwt from "jsonwebtoken";
import crypto from "crypto";
import speakeasy from "speakeasy";

// ===== SIMULACIÓN DE BASE DE DATOS (EN MEMORIA) =====
export const validRefreshTokens = new Map(); // userId -> Set(tokens)
export const activeSessions = new Map();     // sessionId -> { userId, authMethod, createdAt, lastActivity }

// ===== 1. GESTIÓN DE TOKENS (JWT) =====
export function generateAccessToken(userId, email) {
    return jwt.sign({ id: userId, correo: email }, process.env.JWT_SECRET, { expiresIn: "15m" });
}
export function verifyAccessToken(token) { 
    return jwt.verify(token, process.env.JWT_SECRET); 
}
export function generateRefreshToken(userId) {
    return jwt.sign({ id: userId, type: "refresh" },
        process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET, { expiresIn: "7d" });
}
export function verifyRefreshToken(token) {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET);
}
export function storeRefreshToken(userId, token) {
    if (!validRefreshTokens.has(userId)) validRefreshTokens.set(userId, new Set());
    validRefreshTokens.get(userId).add(token);
}
export function revokeRefreshToken(userId, token) {
    if (validRefreshTokens.has(userId)) validRefreshTokens.get(userId).delete(token);
}

// ===== 2. GESTIÓN DE SESIONES DE USUARIO =====
export function createSession(userId, authMethod = "jwt") {
    const sessionId = crypto.randomBytes(16).toString("hex");
    const now = Date.now();
    activeSessions.set(sessionId, { userId, authMethod, createdAt: now, lastActivity: now });
    return sessionId;
}
export function closeSession(sessionId) { 
    return activeSessions.delete(sessionId); 
}
export function getUserActiveSessions(userId) {
    const list = [];
    for (const [sid, s] of activeSessions.entries()) {
        if (s.userId === userId) {
            list.push({
                sessionId: sid,
                authMethod: s.authMethod,
                createdAt: new Date(s.createdAt).toISOString(),
                lastActivity: new Date(s.lastActivity).toISOString(),
            });
        }
    }
    return list;
}

// ===== 3. MIDDLEWARE DE AUTENTICACIÓN JWT =====
export function authenticateJWT(req, res, next) {
    const h = req.headers.authorization;
    if (!h?.startsWith("Bearer ")) return res.status(401).json({ mensaje: "Token requerido" });
    try { 
        const d = verifyAccessToken(h.slice(7)); 
        req.user = d; 
        req.userId = d.id; 
        next(); 
    }
    catch { return res.status(401).json({ mensaje: "Token inválido o expirado" }); }
}

// ===== 4. LÓGICA DE DOBLE FACTOR (2FA) =====
export function generateTempToken(userId, email) {
    return jwt.sign({ id: userId, correo: email, tfa_pending: true }, process.env.JWT_SECRET, { expiresIn: "5m" });
}
export function verifyTempToken(token) {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.tfa_pending) throw new Error("Token no válido para 2FA");
    return decoded;
}
export function generate2FASecret(email) {
    const secret = speakeasy.generateSecret({
        name: `TuApp (${email})`
    });
    return {
        base32: secret.base32,
        otpauth_url: secret.otpauth_url
    };
}
export function verify2FAToken(secret, token) {
    return speakeasy.totp.verify({
        secret: secret,
        encoding: 'base32',
        token: token,
        window: 1
    });
}

// ===== 5. TAREA DE LIMPIEZA AUTOMÁTICA =====
setInterval(() => {
    const now = Date.now();
    const ttl = Number(process.env.SESSION_TTL_MS || 1800000);
    // Limpia solo las sesiones activas, ya que no usamos Access Keys
    for (const [sid, s] of activeSessions.entries()) {
        if (now - s.lastActivity > ttl) activeSessions.delete(sid);
    }
}, Number(process.env.JANITOR_EVERY_MS || 300000));