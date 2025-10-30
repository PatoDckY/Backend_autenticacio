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

import { 
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';

import { isoBase64URL, isoUint8Array } from '@simplewebauthn/server/helpers';

const rpID = process.env.RP_ID || "localhost";
const rpName = "Tu App de Autenticación";
const origin = process.env.FRONTEND_URL || "http://localhost:8080";

const passkeyChallengeStore = new Map();
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
        const enlace = `${process.env.FRONTEND_URL}/magic-login/${token}`;

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

// === PASSKEYS - VERSIÓN 8.3.4 ===

router.post("/passkey/register-options", authenticateJWT, (req, res) => {
    console.log(">>> Petición LLEGÓ a /passkey/register-options v8.3.4");

    if (!req.user || !req.user.id || !req.user.correo) {
        return res.status(500).json({ mensaje: "Error interno: Datos de usuario no encontrados en token." });
    }

    const { id: userId, correo: email } = req.user;

    const sqlGetKeys = "SELECT id FROM passkey_credentials WHERE user_id = ?";

    connection.query(sqlGetKeys, [userId], async (err, results) => {
        if (err) {
            console.error("Error en consulta SELECT passkey_credentials:", err);
            return res.status(500).json({ mensaje: "Error DB", error: err.message });
        }

        const validResults = results.filter(row => row.id && row.id.trim() !== '');
        const excludeCredentials = validResults.map(row => {
            try {
                return {
                    id: isoBase64URL.toBuffer(row.id), // ✅ Convertir a Buffer para v8.3.4
                    type: 'public-key'
                };
            } catch (mapErr) {
                console.error("Error convirtiendo ID a Buffer:", row.id, mapErr);
                return null;
            }
        }).filter(cred => cred !== null);

        try {
            // ✅ v8.3.4: userID como Uint8Array
            const userIdAsUint8Array = isoUint8Array.fromUTF8String(userId.toString());

            const options = await generateRegistrationOptions({
                rpName,
                rpID,
                userID: userIdAsUint8Array,
                userName: email,
                attestationType: 'none',
                excludeCredentials,
                authenticatorSelection: {
                    residentKey: 'preferred',
                    userVerification: 'preferred',
                },
            });

            console.log("Options generadas v8.3.4:", {
                challenge: options.challenge,
                userID: options.user?.id
            });

            passkeyChallengeStore.set(`reg-${userId}`, options.challenge);
            res.json(options);

        } catch (error) {
            console.error("Error en generateRegistrationOptions:", error);
            res.status(500).json({ mensaje: "Error al generar opciones", error: error.message });
        }
    });
});

router.post("/passkey/verify-registration", authenticateJWT, async (req, res) => {
    console.log(">>> Entrando a /verify-registration v8.3.4");
    const { id: userId } = req.user;
    const body = req.body;

    try {
        // Extraer challenge del clientDataJSON
        const clientDataJSON = new TextDecoder().decode(
            isoBase64URL.toBuffer(body.response.clientDataJSON)
        );
        const clientData = JSON.parse(clientDataJSON);
        const expectedChallenge = clientData.challenge;
        
        console.log("Challenge esperado:", expectedChallenge);

        const storedChallenge = passkeyChallengeStore.get(`reg-${userId}`);
        if (storedChallenge !== expectedChallenge) {
            return res.status(400).json({ mensaje: "Challenge no coincide." });
        }

        console.log(">>> Intentando verificar con simplewebauthn v8.3.4...");
        const verification = await verifyRegistrationResponse({
            response: body,
            expectedChallenge: storedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
        });

        console.log("Resultado de verificación:", {
            verified: verification.verified,
            registrationInfo: !!verification.registrationInfo
        });

        if (verification.verified && verification.registrationInfo) {
            // ✅ CORREGIDO: En v8.3.4 los datos están directamente en registrationInfo
            const registrationInfo = verification.registrationInfo;
            
            console.log("RegistrationInfo keys:", Object.keys(registrationInfo));
            
            // Extraer datos directamente de registrationInfo
            const credentialID = registrationInfo.credentialID;
            const credentialPublicKey = registrationInfo.credentialPublicKey;
            const counter = registrationInfo.counter || 0;
            const transportsStr = body.response.transports?.join(',') || '';

            if (!credentialID || !credentialPublicKey) {
                console.error("!!! Datos de credencial faltantes:", {
                    hasCredentialID: !!credentialID,
                    hasCredentialPublicKey: !!credentialPublicKey
                });
                return res.status(500).json({ mensaje: "Error: Datos de credencial incompletos" });
            }

            const idBase64URL = isoBase64URL.fromBuffer(credentialID);
            const publicKeyBase64URL = isoBase64URL.fromBuffer(credentialPublicKey);

            console.log("Datos a guardar:", {
                id: idBase64URL,
                publicKey: publicKeyBase64URL.substring(0, 50) + '...',
                counter,
                transports: transportsStr
            });

            const sqlInsert = `INSERT INTO passkey_credentials (id, user_id, public_key_base64, counter, transports) VALUES (?, ?, ?, ?, ?)`;
            const values = [idBase64URL, userId, publicKeyBase64URL, counter, transportsStr];

            connection.query(sqlInsert, values, (err) => {
                if (err) {
                    console.error("Error al guardar credencial:", err);
                    return res.status(500).json({ mensaje: "Error al guardar credencial", error: err.message });
                }
                
                console.log(">>> Credencial guardada con éxito.");
                passkeyChallengeStore.delete(`reg-${userId}`);
                res.json({ success: true, message: "Passkey registrada." });
            });
        } else {
            res.status(400).json({ mensaje: "Verificación fallida." });
        }
    } catch (error) {
        console.error("Error en verify-registration:", error);
        res.status(500).json({ mensaje: "Error al verificar registro", error: error.message });
    }
});

router.post("/passkey/login-options", async (req, res) => {
    try {
        console.log(">>> Generando opciones de login v8.3.4");
        
        const options = await generateAuthenticationOptions({
            rpID,
            userVerification: 'preferred',
        });

        console.log("Login options generadas v8.3.4:", {
            challenge: options.challenge,
            challengeType: typeof options.challenge
        });

        // Guardar el challenge en el store
        passkeyChallengeStore.set(options.challenge, options.challenge);

        res.json(options);

    } catch (error) {
        console.error("Error en login-options:", error);
        res.status(500).json({ mensaje: "Error al generar opciones de login", error: error.message });
    }
});

router.post("/passkey/verify-login", async (req, res) => {
    console.log(">>> Iniciando verify-login v8.3.4");
    const body = req.body;

    try {
        // Extraer el challenge del clientDataJSON
        const clientDataJSON = new TextDecoder().decode(
            isoBase64URL.toBuffer(body.response.clientDataJSON)
        );
        const clientData = JSON.parse(clientDataJSON);
        const expectedChallenge = clientData.challenge;
        
        console.log("Challenge extraído:", expectedChallenge);

        const storedChallenge = passkeyChallengeStore.get(expectedChallenge);
        if (!storedChallenge) {
            return res.status(400).json({ mensaje: "Challenge no encontrado o expirado." });
        }

        const credentialID = body.rawId || body.id;
        console.log("Buscando credencial con ID:", credentialID);

        const sqlGetKey = "SELECT * FROM passkey_credentials WHERE id = ?";
        
        connection.query(sqlGetKey, [credentialID], async (err, results) => {
            if (err) {
                console.error("Error en DB:", err);
                return res.status(500).json({ mensaje: "Error de base de datos." });
            }
            
            if (results.length === 0) {
                console.error("Credencial no encontrada para ID:", credentialID);
                return res.status(404).json({ mensaje: "Passkey no registrada." });
            }

            const cred = results[0];
            console.log("Credencial encontrada:", {
                id: cred.id,
                counter: cred.counter,
                hasPublicKey: !!cred.public_key_base64
            });

            try {
                // ✅ v8.3.4: Estructura correcta del authenticator
                const authenticator = {
                    credentialID: isoBase64URL.toBuffer(cred.id),
                    credentialPublicKey: isoBase64URL.toBuffer(cred.public_key_base64),
                    counter: parseInt(cred.counter) || 0,
                    transports: cred.transports ? cred.transports.split(',') : [],
                };

                console.log("Authenticator preparado v8.3.4:", {
                    credentialIDLength: authenticator.credentialID.length,
                    credentialPublicKeyLength: authenticator.credentialPublicKey.length,
                    counter: authenticator.counter,
                    transports: authenticator.transports
                });

                const verification = await verifyAuthenticationResponse({
                    response: body,
                    expectedChallenge: storedChallenge,
                    expectedOrigin: origin,
                    expectedRPID: rpID,
                    authenticator,
                });

                console.log("Resultado verificación v8.3.4:", {
                    verified: verification.verified,
                    hasAuthInfo: !!verification.authenticationInfo
                });

                if (verification.verified && verification.authenticationInfo) {
                    const newCounter = verification.authenticationInfo.newCounter;
                    console.log("Nuevo counter:", newCounter);
                    
                    const sqlUpdate = "UPDATE passkey_credentials SET counter = ? WHERE id = ?";
                    connection.query(sqlUpdate, [newCounter, credentialID]);

                    const sqlGetUser = "SELECT * FROM usuarios WHERE id = ?";
                    connection.query(sqlGetUser, [cred.user_id], (errUser, userResults) => {
                        if (errUser || userResults.length === 0) {
                            return res.status(500).json({ mensaje: "Usuario no encontrado." });
                        }

                        const usuario = userResults[0];
                        const accessToken = generateAccessToken(usuario.id, usuario.correo);
                        const refreshToken = generateRefreshToken(usuario.id);
                        storeRefreshToken(usuario.id, refreshToken);
                        const sessionId = createSession(usuario.id, "jwt-passkey");

                        passkeyChallengeStore.delete(expectedChallenge);
                        
                        console.log(">>> Login exitoso para:", usuario.correo);
                        res.json({
                            tfa_required: false,
                            accessToken,
                            refreshToken,
                            sessionId,
                            nombre: usuario.nombre
                        });
                    });
                } else {
                    console.error("Verificación fallida");
                    res.status(401).json({ mensaje: "Verificación de Passkey fallida." });
                }
            } catch (error) {
                console.error("Error en verificación:", error);
                console.error("Stack:", error.stack);
                res.status(500).json({ 
                    mensaje: "Error interno en verificación", 
                    error: error.message 
                });
            }
        });
    } catch (error) {
        console.error("Error general:", error);
        res.status(500).json({ 
            mensaje: "Error procesando la solicitud", 
            error: error.message 
        });
    }
});

export default router;