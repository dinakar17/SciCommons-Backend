import express from 'express';
import * as authController from '../controllers/AuthController';

const router = express.Router();

router.post("/signup", authController.signup);

router.get("/activate/:token", authController.activate);

router.post("/login", authController.login);

router.post("/resendsignupemail", authController.resendSignUpEmail);

router.post("/forgotpassword", authController.forgotPassword);

router.patch("/resetpassword/:token", authController.resetPassword);