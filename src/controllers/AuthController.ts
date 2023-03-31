import crypto from "crypto";
import jwt from 'jsonwebtoken';
import {promisify} from 'util';

import AppError from "../appError";
import { User, UserDocument } from "../models/UserModel";
import catchAsync from "../utils/catchAsync";
import { Request, Response, NextFunction } from "express";
import Email from "../utils/email";
import filterRequestBody from "../utils/filterObj";

// Create and send signup token
const createSendSignUpToken = async (user: UserDocument, req: Request, res: Response, next: NextFunction) => {
    const token = user.createSignupToken();

    // add "signupToken" and "signupTokenExpires" to user document
    await user.save({ validateBeforeSave: false });

    const url = `${req.protocol}://${req.get("host")}/auth/activate/${token}`;

    try {
        await new Email(user, url).sendSignup();
        res.status(200).json({
            status: "success",
            message: "Signup successful. Please check your email for activation link.",
        });
    } catch (err) {
        user.signupToken = undefined;
        user.signupTokenExpires = undefined;
        await user.save({ validateBeforeSave: false });

        return next(new AppError("There was an error sending the email. Please try again later.", 500));
    }
};



export const signup = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const { name, email, password, passwordConfirm } = req.body;
    
    // check if user already exists
    const userExists = await User.findOne({ email });
    if (userExists) {
        return next(new AppError("User already exists", 400));
    }
    
    // save user to DB
    const user = await User.create({ name, email, password, passwordConfirm });

    createSendSignUpToken(user, req, res, next);
});

export const activate = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const allowedFields = ["firstName", "lastName", "bio", "photo", "urls", "positions", "researchInterests"];

    const { token } = req.params;
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    // find user with matching token and token has not expired
    const user = await User.findOne({ signupToken: hashedToken, signupTokenExpires: { $gt: Date.now() } });

    if (!user) {
        return next(new AppError("Your token is invalid or has expired! Please signup again.", 400));
    }

    const filteredBody = filterRequestBody(req.body, allowedFields);

    Object.assign(user, filteredBody); 
    user.emailVerified = true;

    user.signupToken = undefined;
    user.signupTokenExpires = undefined;

    await user.save();

    res.status(200).json({
        status: "success",
        message: "Your account has been registered successfully! We'll send you an email once your account has been approved.",
    });
});

export const resendSignUpEmail = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
        return next(new AppError("There is no user with that email address.", 404));
    }

    if(user.emailVerified) {
        return next(new AppError("Your email has already been verified.", 400));
    }

    createSendSignUpToken(user, req, res, next);
});

const createSendToken = (user: UserDocument, statusCode: number, res: Response) => {
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET!, { expiresIn: process.env.JWT_EXPIRES_IN });

    res.cookie("jwt", token, {
        expires: new Date(Date.now() + parseInt(process.env.JWT_COOKIE_EXPIRES_IN!) * 24 * 60 * 60 * 1000),
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
    });

    // remove password from output
    user.password = undefined as any;
    user.emailVerified = undefined;
    user.verified = undefined;

    res.status(statusCode).json({
        status: "success",
        token,
        data: {
            user,
        },
    });
};

const authVerification = (user: UserDocument | null, next: NextFunction) => {
    if(!user) return next(new AppError("User does not exist, please signup.", 404));

    if(!user.emailVerified) {
        return next(new AppError("Your email has not been verified.", 400));
    }
    if(!user.verified){
        return next(new AppError("We're still reviewing your account. Please check back later.", 400));
    }
    if(!user.active){
        return next(new AppError("Your account has been deactivated.", 400));
    }
}

export const login = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const { email, password } = req.body;

    if(!email || !password) return next(new AppError("Please provide email and password.", 400));

    const user = await User.findOne(email);

    authVerification(user, next);

    createSendToken(user as UserDocument, 200, res);
});


export const forgotPassword = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const {email} = req.body;

    const user = await User.findOne({email});

    authVerification(user , next);

    if(user){
    const resetToken = user.generatePasswordResetToken();

    await user.save({ validateBeforeSave: false });

    const resetURL = `${req.protocol}://${req.get("host")}/auth/forgotpassword/${resetToken}`;

    try {
        await new Email(user, resetURL).sendPasswordReset();
        res.status(200).json({
            status: "success",
            message: "Password reset link sent to email.",
        });
    }
    catch(err){
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({ validateBeforeSave: false });

        return next(new AppError("There was an error sending the email. Please try again later.", 500));
    }
    }
});

export const resetPassword = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const { token } = req.params;
    const { password, passwordConfirm } = req.body;

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({ passwordResetToken: hashedToken, passwordResetExpires: { $gt: Date.now() } });

    if (!user) {
        return next(new AppError("Your token is invalid or has expired! Please try again.", 400));
    }

    user.password = password;
    user.passwordConfirm = passwordConfirm;

    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save();

    res.status(200).json({
        status: "success",
        message: "Your password has been reset successfully! Please login to continue.",
    });
});

export const protect = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
        token = req.headers.authorization.split(" ")[1];
    } else if (req.cookies.jwt) {
        token = req.cookies.jwt;
    }

    if (!token) {
        return next(new AppError("You are not logged in! Please login to get access.", 401));
    }

    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET!);

    const currentUser = await User.findById(decoded.id);

    if (!currentUser) {
        return next(new AppError("The user belonging to this token no longer exists.", 401));
    }

    if (currentUser.changedPasswordAfter(decoded.iat)) {
        return next(new AppError("User recently changed password! Please login again.", 401));
    }

    //@ts-ignore
    req.user = currentUser;

    res.locals.user = currentUser;

    next();
});