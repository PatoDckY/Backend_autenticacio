// import express from "express";
// import nodemailer from "nodemailer";

// const router = express.Router();

// router.get("/", async (req, res) => {
//   try {
//     const transporter = nodemailer.createTransport({
//       service: "gmail",
//       auth: {
//         user: process.env.EMAIL_USER, // correo desde el que se enviará
//         pass: process.env.EMAIL_PASS, // contraseña de aplicación
//       },
//     });

//     const mailOptions = {
//       from: process.env.EMAIL_USER,
//       to: "chavezvargasluisjesusxx@gmail.com", // tu correo para recibir el test
//       subject: "Correo de prueba Nodemailer",
//       text: "¡Hola! Este es un correo de prueba enviado desde Nodemailer.",
//     };

//     await transporter.sendMail(mailOptions);

//     console.log("✅ Correo de prueba enviado correctamente");
//     res.send("Correo de prueba enviado ✅");
//   } catch (error) {
//     console.error("❌ Error al enviar correo de prueba:", error);
//     res.status(500).send("Error al enviar correo de prueba ❌");
//   }
// });

// export default router;
