import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import crypto from 'crypto';

export type UserDocument = mongoose.Document & {
  email: string;
  username: string;
  password: string;
  passwordConfirm: string | undefined;
  firstName: string;
  lastName: string;
  bio: string;
  verified: boolean;
  active: boolean;
  lastPasswordReset: Date;
  signupToken: string;
  signupTokenExpires: Date;
  passwordChangedAt: Date;
  passwordResetToken: string;
  passwordResetExpires: Date;
  comparePassword: (password: string) => Promise<boolean>;
  changedPasswordAfter: (JWTTimestamp: number) => boolean;
  generatePasswordResetToken: () => string;
  createSignupToken: () => string;
  verifySignupToken: (token: string) => boolean;
};


const userSchema = new mongoose.Schema<UserDocument>(
  {
    email: {
      type: String,
      unique: true,
      required: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email address'],
    },
    username: {
      type: String,
      unique: true,
      required: true,
      lowercase: true,
      trim: true,
      minlength: [4, 'Username must be at least 4 characters long'],
    },
    password: {
      type: String,
      required: true,
      minlength: [6, 'Password must be at least 6 characters long'],
    },
    passwordConfirm: {
      type: String,
      required: true,
      validate: {
        validator: function (this: UserDocument, val: string) {
          return val === this.password;
        },
        message: 'Passwords do not match',
      },
    },
    firstName: {
      type: String,
      required: [true, 'First name is required'],
      trim: true,
    },
    lastName: {
      type: String,
      required: [true, 'Last name is required'],
      trim: true, // removes whitespace from both ends of a string
    },
    bio: {
      type: String,
      trim: true,
    },
    verified: {
      type: Boolean,
      default: false,
    },
    active: {
      type: Boolean,
      default: true,
    },
    lastPasswordReset: {
      type: Date,
      default: Date.now,
    },
    signupToken: {
      type: String,
      default: '',
    },
    signupTokenExpires: {
      type: Date,
      default: Date.now,
    },
    passwordChangedAt: Date,
    passwordResetToken: {
      type: String,
      default: '',
    },
    passwordResetExpires: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true },
);

// Hash password before saving to DB
userSchema.pre<UserDocument>('save', async function (next) {
  const user = this;

  // Only hash the password if it has been modified (or is new)
  if (!user.isModified('password')) return next();

  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(user.password, salt);
  user.password = hash;
  user.passwordConfirm = undefined; // Clear passwordConfirm field after validation
  next();
});

// Set passwordChangedAt field to the current time before saving to DB
userSchema.pre<UserDocument>('save', function (next) {
  // Check if the password field has been modified or if this is a new user document
  if (!this.isModified('password') || this.isNew) return next();

  // Set the passwordChangedAt field to the current time with 1 second subtracted
  // This ensures that passwordChangedAt is always earlier than any JWT tokens issued for the user
  this.passwordChangedAt = new Date(Date.now() - 1000);

  next();
});


// Compare password with the hashed password
userSchema.methods.comparePassword = async function (password: string) {
  return bcrypt.compare(password, this.password);
};

// Check if password was changed after a certain time
userSchema.methods.changedPasswordAfter = function (JWTTimestamp: number) {
  if (this.passwordChangedAt) {
    const changedTimestamp = this.passwordChangedAt.getTime() / 1000;
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

// Generate password reset token
userSchema.methods.generatePasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');

this.passwordResetToken = crypto
.createHash('sha256')
.update(resetToken)
.digest('hex');

this.passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000);

return resetToken;
};

// Create signup token
userSchema.methods.createSignupToken = function () {
  const token = crypto.randomBytes(20).toString('hex');
  this.signupToken = crypto.createHash('sha256').update(token).digest('hex');
  this.signupTokenExpires = Date.now() + 24 * 60 * 60 * 1000; // expire in 24 hours
  return token;
};

// Verify signup token
userSchema.methods.verifySignupToken = function (token: string) {
  return this.signupToken === token;
};


export const User = mongoose.model<UserDocument>('User', userSchema);
