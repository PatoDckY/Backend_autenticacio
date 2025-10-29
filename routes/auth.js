import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import connection from "../db.js";
import nodemailer from "nodemailer";

import {
    generateAccessToken,
    generateRefreshToken,
    storeRefreshToken,
    verifyRefreshToken,
    revokeRefreshToken,
    createSession,
    closeSession,
    generateTempToken,
    verifyTempToken,
    generate2FASecret,
    verify2FAToken,
    authenticateJWT
} from "../middlaware/seguridad.js";

const router = express.Router();

// === FLUJO DE AUTENTICACIÓN PRINCIPAL ===

router.post("/register", async (req, res) => {
    const {
        nombre,
        apellido_paterno,
        apellido_materno,
        telefono,
        edad,
        correo,
        contrasena,
    } = req.body;

    if (!nombre || !correo || !contrasena)
        return res.status(400).json({ mensaje: "Faltan datos obligatorios" });

    try {
        const hash = await bcrypt.hash(contrasena, 10);
        const sql = `
            INSERT INTO usuarios 
            (nombre, apellido_paterno, apellido_materno, telefono, edad, correo, contrasena) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;

        connection.query(
            sql,
            [nombre, apellido_paterno, apellido_materno, telefono, edad, correo, hash],
            (err, result) => {
                if (err) {
                    console.error(err);
                    res.status(500).json({ mensaje: "Error al registrar usuario" });
                } else {
                    res.json({ mensaje: "Usuario registrado correctamente" });
                }
            }
        );
    } catch (error) {
        res.status(500).json({ mensaje: "Error interno" });
    }
});

router.post("/login", (req, res) => {
    const { correo, contrasena } = req.body;

    const sql = "SELECT * FROM usuarios WHERE correo = ?";
    connection.query(sql, [correo], async (err, results) => {
        if (err || results.length === 0)
            return res.status(401).json({ mensaje: "Credenciales inválidas" });

        const usuario = results[0];
        const match = await bcrypt.compare(contrasena, usuario.contrasena);

        if (!match)
            return res.status(401).json({ mensaje: "Contrasena incorrecta" });

        if (usuario.tfa_enabled) {
            const tempToken = generateTempToken(usuario.id, usuario.correo);
            res.json({
                tfa_required: true,
                temp_token: tempToken
            });
        } else {
            const accessToken = generateAccessToken(usuario.id, usuario.correo);
            const refreshToken = generateRefreshToken(usuario.id);
            storeRefreshToken(usuario.id, refreshToken);
            const sessionId = createSession(usuario.id, "jwt-password");

            res.json({
                tfa_required: false,
                accessToken,
                refreshToken,
                sessionId,
                nombre: usuario.nombre
            });
        }
    });
});

// === FLUJO DE DOBLE FACTOR (2FA) ===

router.post("/verify-otp", (req, res) => {
    const { temp_token, token } = req.body;

    try {
        const decoded = verifyTempToken(temp_token);
        const userCorreo = decoded.correo;

        const sql = "SELECT id, correo, nombre, tfa_secret FROM usuarios WHERE correo = ?";
        connection.query(sql, [userCorreo], (err, results) => {
            if (err || results.length === 0)
                return res.status(401).json({ mensaje: "Usuario de token no encontrado" });

            const usuario = results[0];
            if (!usuario.tfa_secret)
                return res.status(400).json({ mensaje: "2FA no configurado" });

            const verified = verify2FAToken(usuario.tfa_secret, token);

            if (verified) {
                const accessToken = generateAccessToken(usuario.id, usuario.correo);
                const refreshToken = generateRefreshToken(usuario.id);
                storeRefreshToken(usuario.id, refreshToken);
                const sessionId = createSession(usuario.id, "jwt-2fa");

                res.json({
                    accessToken,
                    refreshToken,
                    sessionId,
                    nombre: usuario.nombre
                });
            } else {
                res.status(401).json({ mensaje: "Código OTP inválido" });
            }
        });

    } catch (error) {
        res.status(401).json({ mensaje: "Token temporal inválido o expirado", error: error.message });
    }
});

router.post("/2fa/setup", authenticateJWT, (req, res) => {
    const { correo: email } = req.user;
    const { base32, otpauth_url } = generate2FASecret(email);

    const sql = "UPDATE usuarios SET tfa_secret = ?, tfa_enabled = 0 WHERE correo = ?";
    connection.query(sql, [base32, email], (err, result) => {
        if (err)
            return res.status(500).json({ mensaje: "Error al guardar secreto en DB" });
        
        res.json({ otpauth_url });
    });
});

router.post("/2fa/enable", authenticateJWT, (req, res) => {
    const { token } = req.body;
    const { correo: email } = req.user;

    const sql = "SELECT tfa_secret FROM usuarios WHERE correo = ?";
    connection.query(sql, [email], (err, results) => {
        if (err || results.length === 0)
            return res.status(404).json({ mensaje: "Usuario no encontrado" });

        const { tfa_secret } = results[0];
        if (!tfa_secret)
            return res.status(400).json({ mensaje: "Llama a /2fa/setup primero" });

        const verified = verify2FAToken(tfa_secret, token);

        if (verified) {
            const updateSql = "UPDATE usuarios SET tfa_enabled = 1 WHERE correo = ?";
            connection.query(updateSql, [email], (updateErr) => {
                if (updateErr)
                    return res.status(500).json({ mensaje: "Error al habilitar 2FA en DB" });
                
                res.json({ success: true, message: "2FA habilitado correctamente." });
            });
        } else {
            res.status(401).json({ success: false, message: "Código OTP inválido." });
        }
    });
});

// === FLUJO DE ENLACE MÁGICO ===

router.post("/magic-link", async (req, res) => {
    const { correo } = req.body;
    if (!correo) return res.status(400).json({ mensaje: "Debes ingresar un correo." });

    try {
        const token = jwt.sign({ correo }, process.env.JWT_SECRET, { expiresIn: "5m" });
        const enlace = `http://localhost:8080/magic-login/${token}`;

        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
        });

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: correo,
            subject: "Tu enlace mágico para iniciar sesión",
            html: `<p>Haz click en este enlace para iniciar sesión:</p>
                   <a href="${enlace}">Iniciar sesión</a>
                   <p>Este enlace expira en 5 minutos.</p>`,
        });

        res.json({ mensaje: "¡Enlace mágico enviado! Revisa tu correo." });
    } catch (error) {
        console.error(error);
        res.status(500).json({ mensaje: "Error al enviar el enlace mágico." });
    }
});

router.post("/magic-login/verify", (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400).json({ mensaje: "Token no proporcionado" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        const sessionToken = jwt.sign(
            { correo: decoded.correo },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({ token: sessionToken, mensaje: "Token válido" });
    } catch (err) {
        res.status(401).json({ mensaje: "Enlace inválido o expirado." });
    }
});

// === GESTIÓN DE SESIÓN ===

router.post("/logout", (req, res) => {
    const { refreshToken, sessionId } = req.body;

    if (!refreshToken || !sessionId) {
        return res.status(400).json({ mensaje: "Faltan datos para cerrar sesión" });
    }

    try {
        const decoded = verifyRefreshToken(refreshToken);
        revokeRefreshToken(decoded.id, refreshToken);
        closeSession(sessionId);
        res.json({ mensaje: "Sesión cerrada correctamente" });
    } catch (err) {
        closeSession(sessionId);
        res.status(401).json({ mensaje: "Token inválido, sesión cerrada" });
    }
});

// === UTILIDADES DE DESARROLLO ===

router.get("/test-mail", async (req, res) => {
    try {
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
        });

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: process.env.EMAIL_USER,
            subject: "Correo de prueba",
            text: "¡Hola! Este es un correo de prueba desde Nodemailer.",
        });

        res.send("Correo enviado correctamente ✅");
    } catch (error) {
        console.error(error);
        res.status(500).send("Error al enviar el correo ❌");
    }
});

export default router;
