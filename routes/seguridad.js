import { Router } from "express";
import {
    // tokens
    generateAccessToken, generateRefreshToken, storeRefreshToken,
    isRefreshTokenValid, verifyRefreshToken,
    // keys
    createUniqueUserKey, getUserKeys, revokeAccessKey,
    // sesiones + middlewares
    createSession, closeSession, getUserActiveSessions,
    authenticateJWT, requireAccessKey, authenticateFlexible, requireActiveSession,
} from "../middlaware/seguridad.js";

const router = Router();

/* ===== PUNTO 1: emitir access token (demo) ===== */
router.post("/tokens/issue", (req, res) => {
    const { userId = "u1", email = "user@example.com" } = req.body || {};
    const accessToken = generateAccessToken(userId, email);
    const refreshToken = generateRefreshToken(userId);
    storeRefreshToken(userId, refreshToken);
    const sessionId = createSession(userId, "jwt");
    res.json({ accessToken, refreshToken, sessionId });
});

/* ===== PUNTO 2: refresh ===== */
router.post("/tokens/refresh", (req, res) => {
    const { userId, refreshToken, email = "" } = req.body || {};
    if (!userId || !refreshToken) return res.status(400).json({ mensaje: "Faltan datos" });
    if (!isRefreshTokenValid(userId, refreshToken))
        return res.status(401).json({ mensaje: "Refresh token inválido" });
    try {
        verifyRefreshToken(refreshToken);
        const accessToken = generateAccessToken(userId, email);
        res.json({ accessToken });
    } catch {
        res.status(401).json({ mensaje: "Refresh token expirado/invalidado" });
    }
});

/* ===== PUNTO 3: sesiones activas ===== */
router.post("/session/open", (req, res) => {
    const { userId = "u1", method = "jwt" } = req.body || {};
    res.json({ sessionId: createSession(userId, method) });
});
router.post("/session/close", (req, res) => {
    const { sessionId } = req.body || {};
    if (!sessionId) return res.status(400).json({ mensaje: "Falta sessionId" });
    closeSession(sessionId); res.json({ ok: true });
});
router.get("/session/:userId", (req, res) => res.json(getUserActiveSessions(req.params.userId)));

/* ===== PUNTO 4 y 5: access keys únicas por usuario ===== */
router.post("/keys/create", (req, res) => {
    const { userId = "u1", ttlMs } = req.body || {};
    res.json(createUniqueUserKey(userId, ttlMs));
});
router.get("/keys/:userId", (req, res) => res.json(getUserKeys(req.params.userId)));
router.post("/keys/revoke", (req, res) => {
    const { key } = req.body || {};
    if (!key) return res.status(400).json({ mensaje: "Falta key" });
    res.json({ ok: revokeAccessKey(key) });
});

/* ===== PUNTO 6: endpoints protegidos para validar accesos ===== */
router.get("/private/jwt", authenticateJWT, (req, res) =>
    res.json({ ok: true, via: "jwt", userId: req.userId })
);
router.get("/private/key", requireAccessKey, (req, res) =>
    res.json({ ok: true, via: "access-key", userId: req.userId })
);
router.get("/private/flex", authenticateFlexible, requireActiveSession, (req, res) =>
    res.json({ ok: true, via: req.user ? "jwt" : "access-key", userId: req.userId, session: req.session })
);

export default router;
