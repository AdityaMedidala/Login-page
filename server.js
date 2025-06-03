const express = require("express");
const nodemailer = require("nodemailer");
const { google } = require("googleapis");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const path = require("path");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");

dotenv.config();

// Validate required environment variables
const requiredEnvVars = [
  'CLIENT_ID', 'CLIENT_SECRET', 'REDIRECT_URI', 
  'REFRESH_TOKEN', 'SENDER_EMAIL', 'MONGODB_URI'
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`❌ Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

const app = express();

// Body parser middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Add request logging middleware
app.use((req, res, next) => {
  console.log(`📝 ${new Date().toISOString()} - ${req.method} ${req.path} from ${req.ip}`);
  console.log(`   Body: ${JSON.stringify(req.body)}`);
  next();
});

// Rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(generalLimiter); // Apply to all requests

const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5, // Limit OTP related requests (send/verify)
  message: { error: "Too many requests, please try again after 5 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req, res) => { // More specific key including email for OTP limits
    return req.ip + (req.body.email || req.body.to || '');
  },
  skip: (req) => {
    // Allow more for localhost development
    return req.ip === '127.0.0.1' || req.ip === '::1' || req.hostname === 'localhost';
  }
});


// Global OAuth2 client - Initialize once
const oAuth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  process.env.REDIRECT_URI
);
oAuth2Client.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  // resetPasswordToken and expires are for link-based reset, not strictly needed for OTP based.
  // resetPasswordToken: String, 
  // resetPasswordExpires: Date 
});
const User = mongoose.model("User", userSchema);

// Schema for regular OTPs (new registration/login)
const otpEntrySchema = new mongoose.Schema({
  email: { type: String, required: true, lowercase: true, trim: true },
  otp: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: '5m' } // Expires in 5 minutes (MongoDB TTL index)
});
otpEntrySchema.index({ email: 1 }); // Index for faster lookups
const OtpEntry = mongoose.model("OtpEntry", otpEntrySchema);


// Schema for Password Reset OTPs
const passwordResetOtpSchema = new mongoose.Schema({
  email: { type: String, required: true, lowercase: true, trim: true },
  otp: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: '5m' } // Expires in 5 minutes
});
passwordResetOtpSchema.index({ email: 1 });
const PasswordResetOtp = mongoose.model("PasswordResetOtp", passwordResetOtpSchema);

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
  // useNewUrlParser: true, // Deprecated
  // useUnifiedTopology: true // Deprecated
  // Mongoose 6+ handles these by default
}).then(() => {
  console.log("✅ MongoDB connected");
}).catch(err => {
  console.error("❌ MongoDB connection error:", err);
  process.exit(1);
});

// Serve static files (like your HTML, CSS, JS if in a 'public' folder)
const publicPath = path.join(__dirname, "public"); // Assuming your HTML is in 'public'
app.use(express.static(publicPath));
// If your HTML is served by a route, ensure that route is defined e.g. app.get('/', ...)

console.log("🔧 Registering API routes...");

// Generate secure 6-digit OTP
function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

// Email validation function
function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Enhanced function to get fresh access token
async function getFreshAccessToken() {
  try {
    const { token } = await oAuth2Client.getAccessToken();
    if (!token) {
      throw new Error('No access token received from Google OAuth2');
    }
    console.log('✅ Fresh access token obtained');
    return token;
  } catch (error) {
    console.error('❌ Access token error:', error.response ? error.response.data : error.message);
    throw new Error(`Failed to get access token: ${error.message}. Check OAuth2 credentials and consent.`);
  }
}

// Enhanced function to create and verify email transporter
async function createEmailTransport() {
  try {
    console.log('🔧 Creating email transporter...');
    const accessToken = await getFreshAccessToken();
    
    const transport = nodemailer.createTransport({
      service: "gmail",
      auth: {
        type: "OAuth2",
        user: process.env.SENDER_EMAIL,
        clientId: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        refreshToken: process.env.REFRESH_TOKEN,
        accessToken: accessToken // Use the fresh token
      },
      tls: {
        rejectUnauthorized: true // Should be true in production
      }
    });

    console.log('🔍 Verifying email transporter...');
    await transport.verify();
    console.log('✅ Email transporter verified successfully');
    return transport;
  } catch (error) {
    console.error('❌ Transporter creation/verification failed:', error.message);
    throw error; // Re-throw to be handled by the caller
  }
}

// Test endpoint for OAuth2 setup
app.get("/test-oauth", async (req, res) => {
  try {
    console.log('🧪 Testing OAuth2 setup...');
    const accessToken = await getFreshAccessToken();
    console.log('✅ Access token test passed');
    const transport = await createEmailTransport(); // This also verifies
    console.log('✅ Email transporter test passed');
    res.json({
      success: true,
      message: "OAuth2 setup and email transporter are working correctly",
      hasAccessToken: !!accessToken,
      timestamp: new Date()
    });
  } catch (error) {
    console.error('❌ OAuth2 test failed:', error);
    res.status(500).json({
      success: false,
      error: "OAuth2 test failed. " + error.message,
      details: error.stack, // Provide stack in test for easier debugging
      timestamp: new Date()
    });
  }
});

// --- API ROUTES ---
app.get("/test", (req, res) => {
  console.log("✅ Test endpoint hit");
  res.json({ 
    message: "Server is working!", 
    timestamp: new Date(),
    routes: ['/test', '/test-oauth', '/sendEmail', '/verifyOtp', '/checkRegistered', '/submitPassword', '/loginWithPassword', '/sendPasswordResetOtp', '/verifyPasswordResetOtp', '/resetPassword']
  });
});

app.post("/checkRegistered", async (req, res) => {
  console.log("📧 Check registration request:", req.body);
  const { email } = req.body;

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ error: "Valid email address is required" });
  }

  try {
    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });
    
    console.log(`🔍 User ${normalizedEmail} registered: ${!!user}`);
    res.status(200).json({ registered: !!user });
  } catch (error) {
    console.error("❌ Check registration error:", error);
    res.status(500).json({ error: "Failed to check registration status. Please try again." });
  }
});

// Send OTP for new user registration / initial OTP login
app.post("/sendEmail", otpLimiter, async (req, res) => {
  console.log("📧 Send OTP (new user/login) request:", req.body);
  const { to } = req.body; // 'to' is used in frontend

  if (!to || !isValidEmail(to)) {
    return res.status(400).json({ error: "Valid email address ('to') is required" });
  }

  const normalizedEmail = to.toLowerCase().trim();
  
  // Optional: Check if user already exists and has a password. 
  // If so, you might want to guide them to password login instead of OTP for an existing account.
  // For this implementation, we assume OTP can be used for new registration or for users who prefer OTP login.

  try {
    console.log(`🚀 Starting OTP send process for: ${normalizedEmail}`);
    const transport = await createEmailTransport();
    const otp = generateOTP();
    console.log("🔢 Generated OTP:", otp);

    const mailOptions = {
      from: `YourApp OTP Service <${process.env.SENDER_EMAIL}>`,
      to: normalizedEmail,
      subject: "Your One-Time Password (OTP)",
      text: `Your OTP code is: ${otp}\n\nThis code will expire in 5 minutes.`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Your One-Time Password (OTP)</h2>
          <p>Your verification code is:</p>
          <div style="background-color: #f0f0f0; padding: 15px 20px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 3px; margin: 20px 0; border-radius: 5px;">
            ${otp}
          </div>
          <p>This code will expire in 5 minutes. Please do not share it with anyone.</p>
          <p style="font-size: 0.9em; color: #777;">If you didn't request this code, please ignore this email.</p>
        </div>
      `
    };

    console.log('📮 Sending email...');
    const result = await transport.sendMail(mailOptions);
    console.log("✅ Email sent successfully:", result.messageId);

    console.log('💾 Saving OTP to database (OtpEntry)...');
    await OtpEntry.deleteMany({ email: normalizedEmail }); // Remove any old OTPs for this email
    await OtpEntry.create({ email: normalizedEmail, otp });
    console.log('✅ OTP saved to database');

    res.status(200).json({
      message: "OTP sent successfully",
      messageId: result.messageId,
      timestamp: new Date()
    });

  } catch (error) {
    console.error("❌ Detailed error sending OTP (/sendEmail):", error.message, error.stack);
    let errorMessage = "Failed to send OTP. Please try again later.";
    // Add more specific error messages based on error codes if needed
    if (error.message.includes("access token")) {
        errorMessage = "OAuth authentication failed. Please check server configuration.";
    }
    res.status(500).json({
      error: errorMessage,
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Verify OTP for new user registration / initial OTP login
app.post("/verifyOtp", otpLimiter, async (req, res) => {
  console.log("🔐 Verify OTP (new user/login) request:", req.body);
  const { email, otp } = req.body;

  if (!email || !isValidEmail(email) || !otp) {
    return res.status(400).json({ error: "Email and OTP are required" });
  }
  if (!/^\d{6}$/.test(otp)) {
    return res.status(400).json({ error: "OTP must be a 6-digit number" });
  }

  try {
    const normalizedEmail = email.toLowerCase().trim();
    const otpEntry = await OtpEntry.findOne({ email: normalizedEmail, otp });

    if (!otpEntry) {
      console.log(`🚫 Invalid or expired OTP for ${normalizedEmail}. OTP tried: ${otp}`);
      return res.status(400).json({ error: "Invalid or expired OTP. Please request a new one." });
    }

    // OTP is valid, remove it
    await OtpEntry.deleteOne({ _id: otpEntry._id });
    console.log("✅ OTP verified successfully for (OtpEntry)", normalizedEmail);
    
    // Frontend will proceed to password creation screen for new user
    res.status(200).json({ message: "OTP verified. Please set your password."});

  } catch (error) {
    console.error("❌ OTP verification error (/verifyOtp):", error);
    res.status(500).json({ error: "OTP verification failed. Please try again." });
  }
});

// Submit password for NEW user (after OTP verification)
app.post("/submitPassword", async (req, res) => {
  console.log("🔑 Submit password (new user registration) request for:", req.body.email);
  const { email, password } = req.body;

  if (!email || !isValidEmail(email) || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters long" });
  }

  try {
    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      // This endpoint is for new user registration. If user exists, something is wrong in flow.
      console.log(`⚠️ Attempt to register existing user via /submitPassword: ${normalizedEmail}`);
      return res.status(409).json({ error: "User already exists. Please login." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email: normalizedEmail, password: hashedPassword });
    await newUser.save();
    console.log("✅ New user registered successfully:", normalizedEmail);
    res.status(201).json({ message: "Registration successful! You can now login." });

  } catch (error) {
    console.error("❌ Submit password (registration) error:", error);
    if (error.code === 11000) { // Duplicate key error (email)
        return res.status(409).json({ error: "Email already registered. Please login." });
    }
    res.status(500).json({ error: "Registration failed. Please try again." });
  }
});

// Login for EXISTING user with password
app.post("/loginWithPassword", async (req, res) => {
  console.log("🔐 Password login request for:", req.body.email);
  const { email, password } = req.body;

  if (!email || !isValidEmail(email) || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      console.log(`🚫 User not found for login: ${normalizedEmail}`);
      return res.status(404).json({ error: "User not found. Please check your email or register." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log(`🚫 Incorrect password for user: ${normalizedEmail}`);
      return res.status(400).json({ error: "Incorrect password. Please try again." });
    }

    console.log("✅ Password login successful for:", normalizedEmail);
    // In a real app, you'd generate a JWT or session token here
    res.status(200).json({ message: "Login successful!" });

  } catch (error) {
    console.error("❌ Password login error:", error);
    res.status(500).json({ error: "Login failed. Please try again." });
  }
});


// --- Password Reset Flow ---

// Send password reset OTP
app.post("/sendPasswordResetOtp", otpLimiter, async (req, res) => {
  console.log("🔄 Send password reset OTP request:", req.body);
  const { to } = req.body; // 'to' from frontend

  if (!to || !isValidEmail(to)) {
    return res.status(400).json({ error: "Valid email address ('to') is required" });
  }
  const normalizedEmail = to.toLowerCase().trim();

  try {
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      // Security: To prevent email enumeration, don't explicitly say "user not found".
      // Log it, and send a generic success-like response.
      console.log(`⚠️ Password reset OTP requested for non-existent email: ${normalizedEmail}`);
      // The frontend will show this message, implying an email might have been sent.
      return res.status(200).json({ message: "If your email is registered, you will receive a password reset OTP." });
    }

    console.log(`🚀 Starting password reset OTP send process for: ${normalizedEmail}`);
    const transport = await createEmailTransport();
    const otp = generateOTP();
    console.log("🔢 Generated password reset OTP:", otp);

    const mailOptions = {
      from: `YourApp Password Reset <${process.env.SENDER_EMAIL}>`,
      to: normalizedEmail,
      subject: "Your Password Reset OTP Code",
      text: `Your password reset OTP code is: ${otp}\n\nThis code will expire in 5 minutes.`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
          <h2 style="color: #333;">Password Reset OTP</h2>
          <p>You requested to reset your password. Your verification code is:</p>
          <div style="background-color: #f0f0f0; padding: 15px 20px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 3px; margin: 20px 0; border-radius: 5px;">
            ${otp}
          </div>
          <p>This code will expire in 5 minutes. Please do not share it.</p>
          <p style="font-size: 0.9em; color: #777;">If you didn't request a password reset, please ignore this email.</p>
        </div>
      `
    };
    await transport.sendMail(mailOptions);
    console.log("✅ Password reset email sent successfully to:", normalizedEmail);

    await PasswordResetOtp.deleteMany({ email: normalizedEmail });
    await PasswordResetOtp.create({ email: normalizedEmail, otp });
    console.log('✅ Password reset OTP saved to database (PasswordResetOtp)');

    res.status(200).json({ message: "Password reset OTP sent successfully." });

  } catch (error) {
    console.error("❌ Error sending password reset OTP:", error.message, error.stack);
    res.status(500).json({ error: "Failed to send password reset OTP. Please try again later." });
  }
});

// Verify password reset OTP
app.post("/verifyPasswordResetOtp", otpLimiter, async (req, res) => {
  console.log("🔐 Verify Password Reset OTP request:", req.body);
  const { email, otp } = req.body;

  if (!email || !isValidEmail(email) || !otp) {
    return res.status(400).json({ error: "Email and OTP are required for password reset verification" });
  }
  if (!/^\d{6}$/.test(otp)) {
    return res.status(400).json({ error: "OTP must be a 6-digit number" });
  }

  try {
    const normalizedEmail = email.toLowerCase().trim();
    const otpEntry = await PasswordResetOtp.findOne({ email: normalizedEmail, otp });

    if (!otpEntry) {
      console.log(`🚫 Invalid or expired password reset OTP for ${normalizedEmail}. OTP tried: ${otp}`);
      return res.status(400).json({ error: "Invalid or expired password reset OTP. Please request a new one." });
    }

    await PasswordResetOtp.deleteOne({ _id: otpEntry._id });
    console.log("✅ Password reset OTP verified successfully for (PasswordResetOtp)", normalizedEmail);
    res.status(200).json({ message: "OTP verified. You can now set a new password." });

  } catch (error) {
    console.error("❌ Password reset OTP verification error:", error);
    res.status(500).json({ error: "Password reset OTP verification failed. Please try again." });
  }
});

// Reset password (after OTP verification)
app.post("/resetPassword", async (req, res) => {
  console.log("🔑 Reset password request for:", req.body.email);
  const { email, password } = req.body;

  if (!email || !isValidEmail(email) || !password) {
    return res.status(400).json({ error: "Email and new password are required" });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "New password must be at least 6 characters long" });
  }

  // Note: The OTP for password reset should have been verified by /verifyPasswordResetOtp just before this call.
  // For added security in a stateless setup, /verifyPasswordResetOtp could return a short-lived token
  // that must be passed to /resetPassword. For this example, we assume direct flow.

  try {
    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      // Should ideally not happen if /sendPasswordResetOtp and /verifyPasswordResetOtp worked.
      console.log(`⚠️ User not found during final password reset stage: ${normalizedEmail}`);
      return res.status(404).json({ error: "User not found. Password reset failed." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    // user.resetPasswordToken = undefined; // If using token-based reset
    // user.resetPasswordExpires = undefined; // If using token-based reset
    await user.save();

    console.log("✅ Password reset successfully for user:", normalizedEmail);
    res.status(200).json({ message: "Password has been reset successfully. You can now login with your new password." });

  } catch (error) {
    console.error("❌ Reset password error:", error);
    res.status(500).json({ error: "Failed to reset password. Please try again." });
  }
});


// Global error handler (optional, for unhandled errors)
app.use((err, req, res, next) => {
  console.error("💥 Unhandled Error:", err.stack);
  res.status(500).json({ error: 'Something broke on the server!' });
});


// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 Frontend probably at http://localhost:${PORT} (if HTML is served by this app)`);
  console.log(`🔗 Test OAuth: http://localhost:${PORT}/test-oauth`);
});
