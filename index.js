import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import fs from "fs";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
const BASE_URL = process.env.BASE_URL;

// Debug middleware to log requests
app.use((req, res, next) => {
  console.log(`📨 ${req.method} ${req.url}`);
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('📦 Request body:', req.body);
  }
  console.log('📋 Content-Type:', req.headers['content-type']);
  next();
});


/* =======================
   File Upload Configuration
======================= */
const uploadDir = 'uploads/';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + '-' + uniqueSuffix + ext);
  }
});
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png|gif|webp|svg|pdf/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('نوع الملف غير مدعوم. يرجى رفع ملفات PDF أو صور فقط (JPEG, JPG, PNG, GIF, WebP, SVG).'));
  }
});
app.use('/uploads', express.static(uploadDir));

/* =======================
   MongoDB Connection
======================= */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB connected");

    setInterval(async () => {
      try {
        await mongoose.connection.db.admin().ping();
        console.log("📡 Pinged MongoDB to stay awake");
      } catch (err) {
        console.error("❌ Ping error:", err);
      }
    }, 5 * 60 * 1000);
  })
  .catch((err) => console.error("❌ MongoDB error:", err));

/* =======================
   Schemas
======================= */

// User Schema
const userSchema = new mongoose.Schema({
  role: { type: String, default: "user" },
  name: { type: String, required: true },
  phone: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  verificationToken: { type: String },
  createdAt: { type: Date, default: Date.now }
});
const adSchema = new mongoose.Schema({
  imageUrl: { type: String, required: true },
  title: { type: String, required: true },
  description: { type: String, required: true },
  buttonText: { type: String, default: 'اعرف المزيد' },
  buttonLink: { type: String, default: '#' },
  isActive: { type: Boolean, default: true },
  order: { type: Number, default: 0 }
}, {
  timestamps: true
});
/* =======================
   Banner Schema (for Animated Banners)
======================= */
const bannerSchema = new mongoose.Schema({
  imageUrl: {
    type: String,
    required: true
  },
  filename: {
    type: String,
    required: true
  },
  originalname: {
    type: String,
    required: true
  },
  path: {
    type: String,
    required: true
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  subtitle: {
    type: String,
    required: true,
    trim: true
  },
  buttonText: {
    type: String,
    default: 'ابدأ الاستثمار الآن'
  },
  buttonLink: {
    type: String,
    default: '#register'
  },
  secondaryButtonText: {
    type: String,
    default: 'اعرف المزيد'
  },
  secondaryButtonLink: {
    type: String,
    default: '#info'
  },
  order: {
    type: Number,
    default: 0
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Create Banner Model
// Admin Schema
const adminSchema = new mongoose.Schema({
  name: { type: String, default: "Admin" },
  phone: { type: String, default: "0000000000" },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isVerified: { type: Boolean, default: true },
  role: { type: String, default: "Admin" },
  createdAt: { type: Date, default: Date.now }
});

// Blacklisted Token Schema
const blacklistedTokenSchema = new mongoose.Schema({
  token: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, required: true },
  role: { type: String, required: true },
  blacklistedAt: { type: Date, default: Date.now, expires: '1d' }
});

// Investment Schema
const investmentSchema = new mongoose.Schema({
  investorName: { type: String, required: true },
  phone: { type: String },
  email: { type: String },
  companyName: { type: String },
  companyType: { type: String, required: true },
  legalStatus: { type: String, required: true },
  commercialReg: { type: String },
  location: { type: String },
  projectName: { type: String, required: true },
  projectDescription: { type: String },
  projectSector: { type: String },
  projectType: { type: String },
  sharesPurchased: { type: Number, required: true, min: 1 },
  sharePrice: { type: Number, required: true, min: 1 },
  totalInvestment: { type: Number, required: true, min: 1 },
  status: { type: String, default: "pending", enum: ["pending", "approved", "rejected", "completed"] },
  notes: { type: String },
  reviewNotes: { type: String },
  reviewDate: { type: Date },
  
  identityFile: {
    filename: String,
    originalname: String,
    path: String,
    size: Number,
    mimetype: String,
    url: String
  },
  
  docsFile: {
    filename: String,
    originalname: String,
    path: String,
    size: Number,
    mimetype: String,
    url: String
  },
  
  paymentProof: {
    filename: String,
    originalname: String,
    path: String,
    size: Number,
    mimetype: String,
    url: String
  },
  
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Project Schema - WITHOUT problematic middleware
const projectSchema = new mongoose.Schema(
  {
    fullName: { type: String, required: true, trim: true },
    phone: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true },
    
    projectName: { type: String, required: true },
    sector: { type: String, required: true },
    type: { type: String, required: true },
    companyName: { type: String, required: true },
    companyType: { type: String, required: true },
    location: { type: String, required: true },
    product: { type: String, required: true },
    cost: { type: Number, required: true },
    personalAmount: { type: Number, default: 0 },
    workers: { type: String },
    clients: { type: String, required: true },
    expectedClients: { type: Number },
    competitors: { type: Number },
    requirements: { type: String },
    branches: { type: Number, default: 0 },
    
    // الحقول الجديدة
    projectImage: {
      filename: String,
      originalname: String,
      path: String,
      size: Number,
      mimetype: String,
      url: String
    },
    
    capitalRequired: { type: Number, default: 0, min: 0 },
    capitalRaised: { type: Number, default: 0, min: 0 },
    fundingDaysLeft: { type: Number, default: 0, min: 0 },
    platformDescription: { type: String, default: '', trim: true },
    votes: { type: Number, default: 0, min: 0 },
    fundingPercentage: { type: Number, default: 0, min: 0, max: 100 },
    isTrending: { type: Boolean, default: false },
    capitalPercentage: { type: Number, default: 0, min: 0, max: 100 },
    daysRemaining: { type: Number, default: 30, min: 0 },
    totalVotes: { type: Number, default: 0, min: 0 },
    projectDetails: { type: String, default: '' },
    
    certificates: [{
      filename: String,
      originalname: String,
      path: String,
      size: Number,
      mimetype: String,
      url: String
    }],
    
    economicStudy: {
      filename: String,
      originalname: String,
      path: String,
      size: Number,
      mimetype: String,
      url: String
    },
    
    complianceFiles: [{
      filename: String,
      originalname: String,
      path: String,
      size: Number,
      mimetype: String,
      url: String
    }],
    
    addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
  },
  { 
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

// REMOVED the problematic middleware and replaced with a document middleware
// We'll handle calculations manually in the routes

// Indexes
projectSchema.index({ projectName: 'text', companyName: 'text', product: 'text', sector: 'text' });
projectSchema.index({ isTrending: -1, votes: -1, createdAt: -1 });
projectSchema.index({ fundingPercentage: -1 });
projectSchema.index({ sector: 1, type: 1 });

// Create Models
const User = mongoose.model("User", userSchema);
const Admin = mongoose.model("Admin", adminSchema);
const BlacklistedToken = mongoose.model("BlacklistedToken", blacklistedTokenSchema);
const Project = mongoose.model("Project", projectSchema);
const Investment = mongoose.model("Investment", investmentSchema);
const Banner = mongoose.model("Banner", bannerSchema);
const Ad = mongoose.model('Ad', adSchema);
/* =======================
   Email Transporter
======================= */
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: "No token provided" });
  }

  const token = authHeader.split(' ')[1];
  
  try {
    const isBlacklisted = await BlacklistedToken.findOne({ token });
    if (isBlacklisted) {
      return res.status(401).json({ success: false, message: "Token is no longer valid. Please login again." });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    req.userRole = decoded.role;
    req.token = token;
    
    let user;
    if (decoded.role === "Admin") {
      user = await Admin.findById(decoded.id);
    } else {
      user = await User.findById(decoded.id);
    }
    
    if (!user) {
      return res.status(401).json({ success: false, message: "User no longer exists" });
    }

    next();
  } catch (error) {
    console.error("❌ Token verification error:", error.message);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: "Token has expired. Please login again." });
    }
    
    return res.status(401).json({ success: false, message: "Invalid token" });
  }
};

/* =======================
   Routes
======================= */
app.get("/", (req, res) => {
  res.send("Backend is running 🚀");
});

/* =======================
   Investment Routes
======================= */
app.post('/api/upload/investment', upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'لم يتم رفع أي ملف' });
    }

    const fileUrl = `/uploads/${req.file.filename}`;
    
    res.status(200).json({
      success: true,
      message: 'تم رفع الملف بنجاح',
      filePath: fileUrl,
      fileName: req.file.originalname,
      fileSize: req.file.size
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء رفع الملف' });
  }
});

app.post("/api/investments", async (req, res) => {
  try {
    console.log("📥 Received investment request:", req.body);
    
    const requiredFields = [
      'investorName', 'companyType', 'legalStatus', 'projectName',
      'sharesPurchased', 'sharePrice', 'totalInvestment'
    ];
    
    for (const field of requiredFields) {
      if (!req.body[field]) {
        return res.status(400).json({ success: false, message: `حقل ${field} مطلوب` });
      }
    }
    
    const investmentData = {
      investorName: req.body.investorName,
      phone: req.body.phone,
      email: req.body.email,
      companyName: req.body.companyName || null,
      companyType: req.body.companyType,
      legalStatus: req.body.legalStatus,
      commercialReg: req.body.commercialReg || null,
      location: req.body.location || null,
      projectName: req.body.projectName,
      projectDescription: req.body.projectDescription || null,
      projectSector: req.body.projectSector || null,
      projectType: req.body.projectType || null,
      sharesPurchased: parseInt(req.body.sharesPurchased),
      sharePrice: parseInt(req.body.sharePrice),
      totalInvestment: parseInt(req.body.totalInvestment),
      status: "pending",
      notes: req.body.notes || null,
    };
    
    const investment = await Investment.create(investmentData);
    
    console.log("✅ Investment saved successfully:", {
      id: investment._id,
      investorName: investment.investorName
    });
    
    res.status(201).json({ success: true, message: 'تم إرسال طلب الاستثمار بنجاح وجاري المراجعة', investment });
  } catch (err) {
    console.error("❌ Error saving investment:", err);
    
    if (err.name === 'ValidationError') {
      const errors = Object.values(err.errors).map(e => e.message);
      return res.status(400).json({ success: false, message: 'خطأ في التحقق من البيانات', errors });
    }
    
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء حفظ الاستثمار', error: err.message });
  }
});

app.get("/api/investments", async (req, res) => {
  try {
    const investments = await Investment.find().sort({ createdAt: -1 });
    console.log(`📊 Fetched ${investments.length} investments`);
    res.json({ success: true, investments });
  } catch (err) {
    console.error("❌ Error fetching investments:", err);
    res.status(500).json({ success: false, message: "حدث خطأ في جلب بيانات الاستثمارات" });
  }
});

app.get("/api/investments/:id", async (req, res) => {
  try {
    const investment = await Investment.findById(req.params.id);
    
    if (!investment) {
      return res.status(404).json({ success: false, message: "الاستثمار غير موجود" });
    }
    
    res.json({ success: true, investment });
  } catch (err) {
    console.error("❌ Error fetching investment:", err);
    res.status(500).json({ success: false, message: "حدث خطأ في جلب بيانات الاستثمار" });
  }
});

app.put("/api/investments/:id/status", async (req, res) => {
  try {
    const { status, reviewNotes } = req.body;
    
    if (!status || !['pending', 'approved', 'rejected', 'completed'].includes(status)) {
      return res.status(400).json({ success: false, message: "حالة غير صالحة" });
    }
    
    const investment = await Investment.findById(req.params.id);
    
    if (!investment) {
      return res.status(404).json({ success: false, message: "الاستثمار غير موجود" });
    }
    
    investment.status = status;
    investment.reviewDate = new Date();
    investment.reviewNotes = reviewNotes || investment.reviewNotes;
    
    await investment.save();
    
    console.log(`✅ Investment status updated: ${investment._id} -> ${status}`);
    
    res.json({ success: true, message: `تم تحديث حالة الاستثمار إلى ${status}`, investment });
  } catch (err) {
    console.error("❌ Error updating investment status:", err);
    res.status(500).json({ success: false, message: "حدث خطأ أثناء تحديث حالة الاستثمار" });
  }
});

app.delete("/api/investments/:id", async (req, res) => {
  try {
    const investment = await Investment.findById(req.params.id);
    
    if (!investment) {
      return res.status(404).json({ success: false, message: "الاستثمار غير موجود" });
    }
    
    await investment.deleteOne();
    
    console.log(`✅ Investment deleted: ${req.params.id}`);
    
    res.json({ success: true, message: "تم حذف الاستثمار بنجاح" });
  } catch (err) {
    console.error("❌ Error deleting investment:", err);
    res.status(500).json({ success: false, message: "حدث خطأ أثناء حذف الاستثمار" });
  }
});

app.get("/api/investments/stats", async (req, res) => {
  try {
    console.log("📊 Fetching investment stats...");
    
    const totalInvestments = await Investment.countDocuments();
    const pendingInvestments = await Investment.countDocuments({ status: 'pending' });
    const approvedInvestments = await Investment.countDocuments({ status: 'approved' });
    const rejectedInvestments = await Investment.countDocuments({ status: 'rejected' });
    const completedInvestments = await Investment.countDocuments({ status: 'completed' });
    
    let totalInvestmentAmount = 0;
    try {
      const result = await Investment.aggregate([
        { 
          $match: { 
            status: { $in: ['approved', 'completed'] },
            totalInvestment: { $exists: true, $ne: null }
          } 
        },
        { 
          $group: { 
            _id: null, 
            total: { $sum: { $ifNull: ['$totalInvestment', 0] } } 
          } 
        }
      ]);
      
      if (result && result.length > 0 && result[0].total !== undefined) {
        totalInvestmentAmount = result[0].total || 0;
      }
    } catch (aggError) {
      console.warn("⚠️ Could not calculate total investment amount:", aggError.message);
      const approvedInvestmentsList = await Investment.find({ 
        status: { $in: ['approved', 'completed'] },
        totalInvestment: { $exists: true, $ne: null }
      });
      totalInvestmentAmount = approvedInvestmentsList.reduce((sum, inv) => {
        return sum + (inv.totalInvestment || 0);
      }, 0);
    }
    
    const stats = {
      totalInvestments: totalInvestments || 0,
      pendingInvestments: pendingInvestments || 0,
      approvedInvestments: approvedInvestments || 0,
      rejectedInvestments: rejectedInvestments || 0,
      completedInvestments: completedInvestments || 0,
      totalInvestmentAmount: totalInvestmentAmount || 0
    };
    
    console.log("✅ Stats fetched successfully:", stats);
    
    res.json({ 
      success: true, 
      stats: stats 
    });
    
  } catch (err) {
    console.error("❌ Error fetching investment stats:", err);
    res.json({
      success: true,
      stats: {
        totalInvestments: 0,
        pendingInvestments: 0,
        approvedInvestments: 0,
        rejectedInvestments: 0,
        completedInvestments: 0,
        totalInvestmentAmount: 0
      }
    });
  }
});

/* =======================
   Auth Routes
======================= */
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, phone, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ success: false, message: "البريد الإلكتروني مستعمل بالفعل" });

    const verificationToken = crypto.randomBytes(32).toString("hex");
    const newUser = new User({ name, phone, email, password, verificationToken });
    await newUser.save();

    const verifyUrl = `${BASE_URL}/api/auth/verify/${verificationToken}`;

    await transporter.sendMail({
      from: `"Ashrik Platform" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "تأكيد البريد الإلكتروني",
      html: `
        <div style="font-family:Arial">
          <h2>مرحبًا ${name}</h2>
          <p>يرجى تأكيد بريدك الإلكتروني لإكمال التسجيل</p>
          <a href="${verifyUrl}" style="display:inline-block;padding:10px 20px;background:#10b981;color:white;text-decoration:none;border-radius:6px">
            تأكيد الحساب
          </a>
        </div>
      `,
    });

    res.status(201).json({ success: true, message: "تم التسجيل بنجاح، يرجى تأكيد البريد الإلكتروني" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "حدث خطأ أثناء التسجيل" });
  }
});

app.get("/api/auth/verify/:token", async (req, res) => {
  try {
    const user = await User.findOne({ verificationToken: req.params.token });
    if (!user) return res.status(400).send("رابط غير صالح أو منتهي");

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    res.send(`
      <html>
        <head>
          <title>تم التأكيد</title>
          <script>
            setTimeout(() => { window.location.href = "http://localhost:3000/login"; }, 3000);
          </script>
        </head>
        <body style="font-family: Arial; text-align:center; margin-top:50px;">
          <h2>تم تأكيد حسابك بنجاح!</h2>
          <p>يمكنك الآن تسجيل الدخول باستخدام حسابك.</p>
          <p>سيتم تحويلك تلقائيًا إلى صفحة تسجيل الدخول خلال 3 ثوانٍ...</p>
          <a href="http://localhost:3000/login">إذا لم يتم التحويل، اضغط هنا</a>
        </body>
      </html>
    `);
  } catch (err) {
    res.status(500).send("خطأ في الخادم");
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log("🔐 Login attempt:", email);

    let user = await Admin.findOne({ email });
    let role = "Admin";
    
    if (!user) {
      user = await User.findOne({ email });
      role = "user";
      
      if (!user) {
        console.log("❌ User not found:", email);
        return res.status(400).json({ success: false, message: "البريد الإلكتروني غير مسجل" });
      }
      
      if (!user.isVerified) {
        return res.status(400).json({ success: false, message: "يرجى تأكيد بريدك الإلكتروني أولاً قبل تسجيل الدخول" });
      }
    }

    if (user.password !== password) {
      console.log("❌ Password incorrect for:", email);
      return res.status(400).json({ success: false, message: "كلمة المرور غير صحيحة." });
    }

    const token = jwt.sign({ id: user._id, role: role, email: user.email }, 
      process.env.JWT_SECRET, { expiresIn: "1d" });

    console.log("✅ Login successful:", { email, role });

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: role,
      },
    });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ success: false, message: "حدث خطأ أثناء تسجيل الدخول" });
  }
});

app.post("/api/auth/logout", verifyToken, async (req, res) => {
  try {
    const { token, userId, userRole } = req;

    console.log("🚪 Logout request for user:", userId);

    await BlacklistedToken.create({
      token,
      userId,
      role: userRole
    });

    console.log("✅ Token blacklisted for user:", userId);

    res.json({ success: true, message: "تم تسجيل الخروج بنجاح" });
  } catch (error) {
    console.error("❌ Logout error:", error);
    res.status(500).json({ success: false, message: "حدث خطأ أثناء تسجيل الخروج" });
  }
});

app.post("/api/auth/logout-all", verifyToken, async (req, res) => {
  try {
    const { userId, userRole } = req;
    
    console.log("🚪 Logout all sessions for user:", userId);
    
    res.json({ success: true, message: "تم تسجيل الخروج من جميع الجلسات بنجاح" });
  } catch (error) {
    console.error("❌ Logout all error:", error);
    res.status(500).json({ success: false, message: "حدث خطأ أثناء تسجيل الخروج" });
  }
});

app.get("/api/auth/validate", verifyToken, async (req, res) => {
  try {
    let user;
    
    if (req.userRole === "Admin") {
      user = await Admin.findById(req.userId, { password: 0 });
    } else {
      user = await User.findById(req.userId, { password: 0, verificationToken: 0 });
    }

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    res.json({
      success: true,
      user: {
        ...user.toObject(),
        role: req.userRole
      },
      isValid: true
    });
  } catch (error) {
    console.error("❌ Token validation error:", error);
    res.status(401).json({ success: false, message: "Invalid token" });
  }
});
/* =======================
   Project Routes
======================= */

// GET all projects - بدون مصادقة
app.get("/api/projects", async (req, res) => {
  try {
    const projects = await Project.find();
    console.log(`📊 Projects fetched: ${projects.length}`);
    res.json({ success: true, projects });
  } catch (err) {
    console.error("❌ Error fetching projects:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET all projects (Admin only - يحتاج مصادقة)
app.get("/api/projects/admin", verifyToken, async (req, res) => {
  try {
    if (req.userRole !== "Admin") {
      return res.status(403).json({ success: false, message: "Unauthorized access" });
    }

    const projects = await Project.find().populate('addedBy', 'name email phone');
    console.log(`📊 Admin projects fetched: ${projects.length}`);
    res.json({ success: true, projects });
  } catch (err) {
    console.error("❌ Error fetching admin projects:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST route to add a project - بدون مصادقة
app.post("/api/projects", upload.fields([
  { name: 'certificates', maxCount: 10 },
  { name: 'economicStudy', maxCount: 1 },
  { name: 'complianceFiles', maxCount: 10 },
  { name: 'image', maxCount: 1 }
]), async (req, res) => {
  try {
    console.log("📦 Incoming project data:", req.body);
    console.log("📁 Incoming files:", req.files);
    
    const cost = parseFloat(req.body.cost) || 0;
    if (cost > 20000000) {
      if (req.files) {
        Object.values(req.files).forEach(fileArray => {
          fileArray.forEach(file => {
            fs.unlink(file.path, (unlinkErr) => {
              if (unlinkErr) console.error("Error deleting file:", unlinkErr);
            });
          });
        });
      }
      
      return res.status(400).json({ 
        success: false, 
        message: "تكلفة المشروع يجب ألا تتجاوز 20,000,000 دج" 
      });
    }
    
    const projectData = {
      fullName: req.body.fullName,
      phone: req.body.phone,
      email: req.body.email.toLowerCase(),
      projectName: req.body.projectName,
      sector: req.body.sector,
      type: req.body.type,
      companyName: req.body.companyName,
      companyType: req.body.companyType,
      location: req.body.location,
      product: req.body.product,
      cost: cost,
      personalAmount: parseFloat(req.body.personalAmount) || 0,
      workers: req.body.workers || '',
      clients: req.body.clients || '',
      expectedClients: parseInt(req.body.expectedClients) || 0,
      competitors: parseInt(req.body.competitors) || 0,
      requirements: req.body.requirements || '',
      branches: parseInt(req.body.branches) || 0,
      
      capitalRaised: parseFloat(req.body.capitalRaised) || 0,
      capitalPercentage: parseInt(req.body.capitalPercentage) || 0,
      daysRemaining: parseInt(req.body.daysRemaining) || 30,
      totalVotes: parseInt(req.body.totalVotes) || 0,
      projectDetails: req.body.projectDetails || '',
      addedBy: null,
      certificates: [],
      complianceFiles: []
    };
    
    if (req.files && req.files['image']) {
      const file = req.files['image'][0];
      projectData.projectImage = {
        filename: file.filename,
        originalname: file.originalname,
        path: file.path,
        size: file.size,
        mimetype: file.mimetype,
        url: `/uploads/${file.filename}`
      };
    }
    
    if (req.files && req.files['certificates']) {
      projectData.certificates = req.files['certificates'].map(file => ({
        filename: file.filename,
        originalname: file.originalname,
        path: file.path,
        size: file.size,
        mimetype: file.mimetype,
        url: `/uploads/${file.filename}`
      }));
    }
    
    if (req.files && req.files['economicStudy']) {
      const file = req.files['economicStudy'][0];
      projectData.economicStudy = {
        filename: file.filename,
        originalname: file.originalname,
        path: file.path,
        size: file.size,
        mimetype: file.mimetype,
        url: `/uploads/${file.filename}`
      };
    }
    
    if (req.files && req.files['complianceFiles']) {
      projectData.complianceFiles = req.files['complianceFiles'].map(file => ({
        filename: file.filename,
        originalname: file.originalname,
        path: file.path,
        size: file.size,
        mimetype: file.mimetype,
        url: `/uploads/${file.filename}`
      }));
    }
    
    // Manually calculate percentages before saving
    const capitalRequired = Number(projectData.capitalRequired) || 0;
    const capitalRaised = Number(projectData.capitalRaised) || 0;
    
    if (capitalRequired > 0) {
      projectData.fundingPercentage = Math.min(Math.round((capitalRaised / capitalRequired) * 100), 100);
    } else {
      projectData.fundingPercentage = 0;
    }
    
    if ((projectData.capitalPercentage === 0 || !projectData.capitalPercentage) && capitalRequired > 0) {
      projectData.capitalPercentage = Math.min(Math.round((capitalRaised / capitalRequired) * 100), 100);
    }
    
    const project = await Project.create(projectData);
    
    console.log("✅ Project saved successfully:", {
      id: project._id,
      projectName: project.projectName,
      cost: project.cost,
      hasImage: !!project.projectImage
    });
    
    res.status(201).json({ success: true, project, message: "تم حفظ المشروع بنجاح" });
    
  } catch (err) {
    console.error("❌ Error saving project:", err);
    
    if (req.files) {
      Object.values(req.files).forEach(fileArray => {
        fileArray.forEach(file => {
          fs.unlink(file.path, (unlinkErr) => {
            if (unlinkErr) console.error("Error deleting file:", unlinkErr);
          });
        });
      });
    }
    
    res.status(500).json({ success: false, message: err.message || "حدث خطأ أثناء حفظ المشروع" });
  }
});

// GET single project - بدون مصادقة
app.get("/api/projects/:id", async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    
    if (!project) {
      return res.status(404).json({ success: false, message: "Project not found" });
    }
    
    res.json({ success: true, project });
  } catch (err) {
    console.error("❌ Error fetching project:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ✅ FIXED: UPDATE project - بدون مصادقة (للجميع) - WITH IMAGE UPLOAD
app.put("/api/projects/:id", upload.single('image'), async (req, res) => {
  try {
    console.log(`📝 Updating project with image: ${req.params.id}`);
    console.log("📦 Request body fields:", Object.keys(req.body));
    console.log("🖼️ Request file:", req.file ? `Present: ${req.file.filename}` : "None");
    
    const project = await Project.findById(req.params.id);
    
    if (!project) {
      // Delete uploaded file if project not found
      if (req.file) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting uploaded file:", err);
        });
      }
      return res.status(404).json({ success: false, message: "Project not found" });
    }
    
    // Handle image upload if provided
    if (req.file) {
      console.log("🖼️ Processing image upload:", req.file.filename);
      
      // Delete old image if exists
      if (project.projectImage && project.projectImage.filename) {
        const oldImagePath = path.join(__dirname, '..', 'uploads', project.projectImage.filename);
        fs.unlink(oldImagePath, (err) => {
          if (err) console.error("❌ Error deleting old image:", err);
        });
      }
      
      project.projectImage = {
        filename: req.file.filename,
        originalname: req.file.originalname,
        path: req.file.path,
        size: req.file.size,
        mimetype: req.file.mimetype,
        url: `/uploads/${req.file.filename}`
      };
    }
    
    // Parse FormData fields if they exist
    let updateData = {};
    if (req.body) {
      // Try to parse JSON fields from FormData
      try {
        if (req.body.capitalRaised !== undefined) updateData.capitalRaised = parseFloat(req.body.capitalRaised) || 0;
        if (req.body.capitalPercentage !== undefined) updateData.capitalPercentage = parseFloat(req.body.capitalPercentage) || 0;
        if (req.body.daysRemaining !== undefined) updateData.daysRemaining = parseInt(req.body.daysRemaining) || 30;
        if (req.body.totalVotes !== undefined) updateData.totalVotes = parseInt(req.body.totalVotes) || 0;
        if (req.body.projectDetails !== undefined) updateData.projectDetails = req.body.projectDetails;
      } catch (e) {
        console.log("⚠️ Could not parse some fields:", e.message);
      }
    }
    
    // Update fields from parsed data
    const updatableFields = [
      'capitalRaised', 'capitalPercentage', 'daysRemaining', 
      'totalVotes', 'projectDetails', 'capitalRequired'
    ];
    
    updatableFields.forEach(field => {
      if (updateData[field] !== undefined) {
        project[field] = updateData[field];
      }
    });
    
    // ✅ Manually calculate percentages
    const capitalRequired = Number(project.capitalRequired) || 0;
    const capitalRaised = Number(project.capitalRaised) || 0;
    
    if (capitalRequired > 0) {
      project.fundingPercentage = Math.min(Math.round((capitalRaised / capitalRequired) * 100), 100);
    } else {
      project.fundingPercentage = 0;
    }
    
    if ((project.capitalPercentage === 0 || !project.capitalPercentage) && capitalRequired > 0) {
      project.capitalPercentage = Math.min(Math.round((capitalRaised / capitalRequired) * 100), 100);
    }
    
    // Save without triggering validation
    await project.save({ validateBeforeSave: false });
    
    console.log("✅ Project updated successfully:", {
      id: project._id,
      projectName: project.projectName,
      capitalRaised: project.capitalRaised,
      capitalPercentage: project.capitalPercentage,
      hasImage: !!project.projectImage,
      imageUrl: project.projectImage?.url
    });
    
    res.json({ 
      success: true, 
      message: "تم تحديث المشروع بنجاح", 
      project 
    });
    
  } catch (err) {
    console.error("❌ Error updating project:", err);
    
    // Delete uploaded file if there was an error
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error("Error deleting uploaded file:", err);
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: err.message || "حدث خطأ أثناء تحديث المشروع" 
    });
  }
});

// ✅ FIXED: UPDATE project details - بدون مصادقة - WITH IMAGE UPLOAD
app.put("/api/projects/:id/update-details", upload.single('image'), async (req, res) => {
  try {
    console.log(`📝 Updating project details with image: ${req.params.id}`);
    console.log("📦 Request data received");
    console.log("🖼️ Request file:", req.file ? `Present: ${req.file.filename}` : "None");
    
    const project = await Project.findById(req.params.id);
    
    if (!project) {
      // Delete uploaded file if project not found
      if (req.file) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting uploaded file:", err);
        });
      }
      return res.status(404).json({ success: false, message: "Project not found" });
    }
    
    // Parse FormData fields
    const updateData = {};
    if (req.body) {
      // Parse numeric fields
      if (req.body.capitalRaised !== undefined) updateData.capitalRaised = parseFloat(req.body.capitalRaised) || 0;
      if (req.body.capitalPercentage !== undefined) updateData.capitalPercentage = parseFloat(req.body.capitalPercentage) || 0;
      if (req.body.daysRemaining !== undefined) updateData.daysRemaining = parseInt(req.body.daysRemaining) || 30;
      if (req.body.totalVotes !== undefined) updateData.totalVotes = parseInt(req.body.totalVotes) || 0;
      if (req.body.projectDetails !== undefined) updateData.projectDetails = req.body.projectDetails;
      if (req.body.capitalRequired !== undefined) updateData.capitalRequired = parseFloat(req.body.capitalRequired) || 0;
    }
    
    // Handle image upload if provided
    if (req.file) {
      console.log("🖼️ Processing image upload:", req.file.filename);
      
      // Delete old image if exists
      if (project.projectImage && project.projectImage.filename) {
        const oldImagePath = path.join(__dirname, '..', 'uploads', project.projectImage.filename);
        fs.unlink(oldImagePath, (err) => {
          if (err) console.error("❌ Error deleting old image:", err);
        });
      }
      
      project.projectImage = {
        filename: req.file.filename,
        originalname: req.file.originalname,
        path: req.file.path,
        size: req.file.size,
        mimetype: req.file.mimetype,
        url: `/uploads/${req.file.filename}`
      };
    }
    
    // Update fields from parsed data
    const updatableFields = [
      'capitalRaised', 'capitalPercentage', 'daysRemaining', 
      'totalVotes', 'projectDetails', 'capitalRequired'
    ];
    
    let hasChanges = false;
    
    updatableFields.forEach(field => {
      if (updateData[field] !== undefined) {
        hasChanges = true;
        project[field] = updateData[field];
      }
    });
    
    // If image was uploaded, we have changes
    if (req.file) hasChanges = true;
    
    if (!hasChanges) {
      // Delete uploaded file if no changes
      if (req.file) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting uploaded file:", err);
        });
      }
      return res.status(400).json({ 
        success: false, 
        message: "No fields to update" 
      });
    }
    
    // ✅ Manually calculate percentages
    const capitalRequired = Number(project.capitalRequired) || 0;
    const capitalRaised = Number(project.capitalRaised) || 0;
    
    if (capitalRequired > 0) {
      project.fundingPercentage = Math.min(Math.round((capitalRaised / capitalRequired) * 100), 100);
    } else {
      project.fundingPercentage = 0;
    }
    
    if ((project.capitalPercentage === 0 || !project.capitalPercentage) && capitalRequired > 0) {
      project.capitalPercentage = Math.min(Math.round((capitalRaised / capitalRequired) * 100), 100);
    }
    
    // Save without validation
    await project.save({ validateBeforeSave: false });
    
    console.log("✅ Project details updated successfully:", {
      id: project._id,
      projectName: project.projectName,
      capitalRaised: project.capitalRaised,
      capitalPercentage: project.capitalPercentage,
      hasImage: !!project.projectImage,
      imageUrl: project.projectImage?.url
    });
    
    res.json({ 
      success: true, 
      message: "تم تحديث تفاصيل المشروع بنجاح", 
      project 
    });
    
  } catch (err) {
    console.error("❌ Error updating project details:", err);
    
    // Delete uploaded file if error
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error("Error deleting uploaded file:", err);
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: err.message || "حدث خطأ أثناء تحديث المشروع" 
    });
  }
});

// ✅ SIMPLE update endpoint for project details (JSON only - no images)
app.put("/api/projects/:id/update-simple", async (req, res) => {
  try {
    console.log(`📝 Simple update for project: ${req.params.id}`);
    
    const { capitalRaised, capitalPercentage, daysRemaining, totalVotes, projectDetails } = req.body;
    
    const project = await Project.findById(req.params.id);
    if (!project) {
      return res.status(404).json({ success: false, message: "Project not found" });
    }
    
    // Only update provided fields
    if (capitalRaised !== undefined) project.capitalRaised = parseFloat(capitalRaised) || 0;
    if (capitalPercentage !== undefined) project.capitalPercentage = parseFloat(capitalPercentage) || 0;
    if (daysRemaining !== undefined) project.daysRemaining = parseInt(daysRemaining) || 30;
    if (totalVotes !== undefined) project.totalVotes = parseInt(totalVotes) || 0;
    if (projectDetails !== undefined) project.projectDetails = projectDetails;
    
    // Recalculate funding percentage if capitalRaised changed
    if (capitalRaised !== undefined) {
      const capitalRequired = Number(project.capitalRequired) || 0;
      const capitalRaisedNum = Number(project.capitalRaised) || 0;
      
      if (capitalRequired > 0) {
        project.fundingPercentage = Math.min(Math.round((capitalRaisedNum / capitalRequired) * 100), 100);
      }
    }
    
    await project.save({ validateBeforeSave: false });
    
    console.log("✅ Simple update successful for:", project._id);
    res.json({ success: true, message: "تم التحديث بنجاح", project });
    
  } catch (err) {
    console.error("❌ Simple update error:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// JSON-only update route (without file upload)
app.put("/api/projects/:id/update", async (req, res) => {
  try {
    console.log(`📝 Updating project (JSON): ${req.params.id}`);
    
    // Check if request body exists
    if (!req.body || Object.keys(req.body).length === 0) {
      console.log("⚠️ Request body is empty");
      return res.status(400).json({ 
        success: false, 
        message: "Request body is empty or invalid" 
      });
    }
    
    console.log("📦 Request data:", req.body);
    
    const project = await Project.findById(req.params.id);
    
    if (!project) {
      return res.status(404).json({ success: false, message: "Project not found" });
    }
    
    // Update all fields except files
    const updatableFields = [
      'fullName', 'phone', 'email', 'projectName', 'sector', 'type',
      'companyName', 'companyType', 'location', 'product', 'cost',
      'personalAmount', 'workers', 'clients', 'expectedClients',
      'competitors', 'requirements', 'branches', 'capitalRequired',
      'capitalRaised', 'fundingDaysLeft', 'platformDescription',
      'votes', 'isTrending', 'capitalPercentage', 'daysRemaining',
      'totalVotes', 'projectDetails'
    ];
    
    updatableFields.forEach(field => {
      if (req.body[field] !== undefined && req.body[field] !== null) {
        const value = req.body[field];
        
        if (field === 'cost' || field === 'personalAmount' || 
            field === 'capitalRequired' || field === 'capitalRaised') {
          project[field] = parseFloat(value) || 0;
        } else if (field === 'expectedClients' || field === 'competitors' || 
                   field === 'branches' || field === 'capitalPercentage' || 
                   field === 'daysRemaining' || field === 'totalVotes' || 
                   field === 'fundingDaysLeft' || field === 'votes') {
          project[field] = parseInt(value) || 0;
        } else if (field === 'isTrending') {
          // Handle both string "true"/"false" and boolean
          if (typeof value === 'string') {
            project[field] = value.toLowerCase() === 'true';
          } else {
            project[field] = Boolean(value);
          }
        } else {
          project[field] = value;
        }
      }
    });
    
    // Recalculate percentages
    const capitalRequired = Number(project.capitalRequired) || 0;
    const capitalRaised = Number(project.capitalRaised) || 0;
    
    if (capitalRequired > 0) {
      project.fundingPercentage = Math.min(
        Math.round((capitalRaised / capitalRequired) * 100), 
        100
      );
    }
    
    await project.save({ validateBeforeSave: false });
    
    console.log("✅ Project updated successfully (JSON):", {
      id: project._id,
      projectName: project.projectName
    });
    
    res.json({ 
      success: true, 
      message: "تم تحديث المشروع بنجاح", 
      project 
    });
    
  } catch (err) {
    console.error("❌ Error updating project (JSON):", err);
    res.status(500).json({ 
      success: false, 
      message: err.message || "حدث خطأ أثناء تحديث المشروع" 
    });
  }
});

// DELETE project - بدون مصادقة (للجميع)
app.delete("/api/projects/:id", async (req, res) => {
  try {
    console.log(`🗑️ Deleting project: ${req.params.id}`);
    
    const project = await Project.findById(req.params.id);
    
    if (!project) {
      return res.status(404).json({ success: false, message: "Project not found" });
    }
    
    if (project.projectImage && project.projectImage.filename) {
      fs.unlink(project.projectImage.path, (err) => {
        if (err) console.error("❌ Error deleting project image:", err);
      });
    }
    
    if (project.certificates && project.certificates.length > 0) {
      project.certificates.forEach(cert => {
        if (cert.path) {
          fs.unlink(cert.path, (err) => {
            if (err) console.error("❌ Error deleting certificate:", err);
          });
        }
      });
    }
    
    if (project.complianceFiles && project.complianceFiles.length > 0) {
      project.complianceFiles.forEach(file => {
        if (file.path) {
          fs.unlink(file.path, (err) => {
            if (err) console.error("❌ Error deleting compliance file:", err);
          });
        }
      });
    }
    
    if (project.economicStudy && project.economicStudy.path) {
      fs.unlink(project.economicStudy.path, (err) => {
        if (err) console.error("❌ Error deleting economic study:", err);
      });
    }
    
    await project.deleteOne();
    
    console.log("✅ Project deleted successfully:", {
      id: req.params.id,
      projectName: project.projectName
    });
    
    res.json({ success: true, message: "تم حذف المشروع بنجاح" });
  } catch (err) {
    console.error("❌ Error deleting project:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// VOTE for a project - بدون مصادقة
app.post("/api/projects/:id/vote", async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    
    if (!project) {
      return res.status(404).json({ success: false, message: "Project not found" });
    }
    
    project.votes = (project.votes || 0) + 1;
    
    await project.save();
    
    console.log("✅ Vote recorded:", {
      id: project._id,
      projectName: project.projectName,
      newVoteCount: project.votes
    });
    
    res.json({ success: true, message: "تم تسجيل تصويتك بنجاح", votes: project.votes });
    
  } catch (err) {
    console.error("❌ Error voting for project:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET projects statistics - بدون مصادقة
app.get("/api/projects/stats", async (req, res) => {
  try {
    const totalProjects = await Project.countDocuments();
    
    // Safe aggregation with fallback
    let totalVotes = 0;
    try {
      const votesResult = await Project.aggregate([
        { $group: { _id: null, totalVotes: { $sum: { $ifNull: ["$votes", 0] } } } }
      ]);
      totalVotes = votesResult[0]?.totalVotes || 0;
    } catch (e) {
      console.warn("Could not aggregate votes:", e.message);
    }
    
    let totalCapitalRequired = 0;
    try {
      const capitalRequiredResult = await Project.aggregate([
        { $group: { _id: null, totalCapitalRequired: { $sum: { $ifNull: ["$capitalRequired", 0] } } } }
      ]);
      totalCapitalRequired = capitalRequiredResult[0]?.totalCapitalRequired || 0;
    } catch (e) {
      console.warn("Could not aggregate capital required:", e.message);
    }
    
    let totalCapitalRaised = 0;
    try {
      const capitalRaisedResult = await Project.aggregate([
        { $group: { _id: null, totalCapitalRaised: { $sum: { $ifNull: ["$capitalRaised", 0] } } } }
      ]);
      totalCapitalRaised = capitalRaisedResult[0]?.totalCapitalRaised || 0;
    } catch (e) {
      console.warn("Could not aggregate capital raised:", e.message);
    }
    
    const trendingProjects = await Project.countDocuments({ isTrending: true });
    
    res.json({
      success: true,
      stats: {
        totalProjects: totalProjects || 0,
        totalVotes: totalVotes || 0,
        totalCapitalRequired: totalCapitalRequired || 0,
        totalCapitalRaised: totalCapitalRaised || 0,
        trendingProjects: trendingProjects || 0
      }
    });
    
  } catch (err) {
    console.error("❌ Error fetching project stats:", err);
    res.json({
      success: true,
      stats: {
        totalProjects: 0,
        totalVotes: 0,
        totalCapitalRequired: 0,
        totalCapitalRaised: 0,
        trendingProjects: 0
      }
    });
  }
});

// UPDATE project details (Admin only) - محفوظة للمشرفين
app.put("/api/projects/:id/details", verifyToken, async (req, res) => {
  try {
    if (req.userRole !== "Admin") {
      return res.status(403).json({ success: false, message: "Unauthorized access" });
    }

    const project = await Project.findById(req.params.id);
    
    if (!project) {
      return res.status(404).json({ success: false, message: "Project not found" });
    }
    
    const {
      projectImage,
      capitalRequired,
      capitalRaised,
      fundingDaysLeft,
      platformDescription,
      isTrending
    } = req.body;
    
    if (projectImage !== undefined) project.projectImage = projectImage;
    if (capitalRequired !== undefined) project.capitalRequired = parseFloat(capitalRequired) || 0;
    if (capitalRaised !== undefined) project.capitalRaised = parseFloat(capitalRaised) || 0;
    if (fundingDaysLeft !== undefined) project.fundingDaysLeft = parseInt(fundingDaysLeft) || 0;
    if (platformDescription !== undefined) project.platformDescription = platformDescription;
    if (isTrending !== undefined) project.isTrending = isTrending;
    
    await project.save({ validateBeforeSave: false });
    
    console.log("✅ Project details updated:", {
      id: project._id,
      projectName: project.projectName
    });
    
    res.json({ success: true, message: "تم تحديث تفاصيل المشروع بنجاح", project });
    
  } catch (err) {
    console.error("❌ Error updating project details:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// UPDATE project image (Admin only) - محفوظة للمشرفين
app.put("/api/projects/:id/image", verifyToken, upload.single('projectImage'), async (req, res) => {
  try {
    if (req.userRole !== "Admin") {
      if (req.file) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting uploaded image:", err);
        });
      }
      return res.status(403).json({ success: false, message: "Unauthorized access" });
    }

    const project = await Project.findById(req.params.id);
    
    if (!project) {
      if (req.file) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting uploaded image:", err);
        });
      }
      return res.status(404).json({ success: false, message: "Project not found" });
    }
    
    if (!req.file) {
      return res.status(400).json({ success: false, message: "لم يتم رفع أي صورة" });
    }
    
    if (project.projectImage && project.projectImage.filename) {
      const oldImagePath = path.join(__dirname, '..', 'uploads', project.projectImage.filename);
      fs.unlink(oldImagePath, (err) => {
        if (err) console.error("Error deleting old image:", err);
      });
    }
    
    project.projectImage = {
      filename: req.file.filename,
      originalname: req.file.originalname,
      path: req.file.path,
      size: req.file.size,
      mimetype: req.file.mimetype,
      url: `/uploads/${req.file.filename}`
    };
    
    await project.save({ validateBeforeSave: false });
    
    console.log("✅ Project image updated:", {
      id: project._id,
      projectName: project.projectName,
      imageUrl: project.projectImage.url
    });
    
    res.json({ success: true, message: "تم تحديث صورة المشروع بنجاح", image: project.projectImage });
    
  } catch (err) {
    console.error("❌ Error updating project image:", err);
    
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error("Error deleting uploaded image:", err);
      });
    }
    
    res.status(500).json({ success: false, message: err.message });
  }
});
// Add this route to your backend
app.get("/api/projects/needing-funding", async (req, res) => {
  try {
    const projects = await Project.find({
      $or: [
        { capitalPercentage: { $lt: 100 } },
        { capitalPercentage: { $exists: false } }
      ],
      daysRemaining: { $gt: 0 }
    }).sort({ createdAt: -1 });
    
    console.log(`📊 Projects needing funding: ${projects.length}`);
    res.json({ success: true, projects });
  } catch (err) {
    console.error("❌ Error fetching projects needing funding:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});
/* =======================
   Admin Management Routes
======================= */
app.get("/api/admins", verifyToken, async (req, res) => {
  try {
    if (req.userRole !== "Admin") {
      return res.status(403).json({ success: false, message: "Unauthorized access" });
    }

    const admins = await Admin.find({}, { password: 0 });
    console.log(`📊 Fetched ${admins.length} admins`);
    res.json({ success: true, admins });
  } catch (error) {
    console.error("❌ Error fetching admins:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/api/admins", verifyToken, async (req, res) => {
  try {
    if (req.userRole !== "Admin") {
      return res.status(403).json({ success: false, message: "Unauthorized access" });
    }

    const { name, email, phone, password } = req.body;

    console.log("📝 Creating admin with data:", { name, email, phone });

    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      return res.status(400).json({ success: false, message: "البريد الإلكتروني مستعمل بالفعل" });
    }

    const newAdmin = new Admin({
      name: name || "Admin",
      email,
      phone: phone || "0000000000",
      password: password,
      isVerified: true,
      role: "Admin"
    });

    await newAdmin.save();

    const adminResponse = {
      _id: newAdmin._id,
      name: newAdmin.name,
      email: newAdmin.email,
      phone: newAdmin.phone,
      role: newAdmin.role,
      isVerified: newAdmin.isVerified,
      createdAt: newAdmin.createdAt
    };

    console.log("✅ Admin created:", adminResponse);
    res.status(201).json({ success: true, admin: adminResponse });
  } catch (error) {
    console.error("❌ Error creating admin:", error);
    res.status(500).json({ success: false, message: "حدث خطأ أثناء إنشاء المشرف" });
  }
});

app.put("/api/admins/:id", verifyToken, async (req, res) => {
  try {
    if (req.userRole !== "Admin") {
      return res.status(403).json({ success: false, message: "Unauthorized access" });
    }

    const { name, email, phone, password } = req.body;
    
    console.log("📝 Updating admin:", req.params.id, { name, email, phone });
    
    const admin = await Admin.findById(req.params.id);
    if (!admin) {
      return res.status(404).json({ success: false, message: "المشرف غير موجود" });
    }

    if (name) admin.name = name;
    if (email) admin.email = email;
    if (phone) admin.phone = phone;
    if (password) admin.password = password;

    await admin.save();

    const adminResponse = {
      _id: admin._id,
      name: admin.name,
      email: admin.email,
      phone: admin.phone,
      role: admin.role,
      isVerified: admin.isVerified,
      createdAt: admin.createdAt
    };

    console.log("✅ Admin updated:", adminResponse);
    res.json({ success: true, admin: adminResponse });
  } catch (error) {
    console.error("❌ Error updating admin:", error);
    res.status(500).json({ success: false, message: "حدث خطأ أثناء تحديث المشرف" });
  }
});

app.delete("/api/admins/:id", verifyToken, async (req, res) => {
  try {
    if (req.userRole !== "Admin") {
      return res.status(403).json({ success: false, message: "Unauthorized access" });
    }

    console.log("🗑️ Deleting admin:", req.params.id);
    
    const admin = await Admin.findByIdAndDelete(req.params.id);
    
    if (!admin) {
      return res.status(404).json({ success: false, message: "المشرف غير موجود" });
    }

    console.log("✅ Admin deleted:", admin._id);
    res.json({ success: true, message: "تم حذف المشرف بنجاح", deletedId: admin._id });
  } catch (error) {
    console.error("❌ Error deleting admin:", error);
    res.status(500).json({ success: false, message: "حدث خطأ أثناء حذف المشرف" });
  }
});

app.get("/api/admins/:id", verifyToken, async (req, res) => {
  try {
    if (req.userRole !== "Admin") {
      return res.status(403).json({ success: false, message: "Unauthorized access" });
    }

    const admin = await Admin.findById(req.params.id, { password: 0 });
    
    if (!admin) {
      return res.status(404).json({ success: false, message: "المشرف غير موجود" });
    }

    res.json({ success: true, admin });
  } catch (error) {
    console.error("❌ Error fetching admin:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

/* =======================
   User Management Routes
======================= */
app.get("/api/users", verifyToken, async (req, res) => {
  try {
    if (req.userRole !== "Admin") {
      return res.status(403).json({ success: false, message: "Unauthorized access" });
    }

    const users = await User.find({}, { password: 0, verificationToken: 0 });
    console.log(`📊 Fetched ${users.length} users`);
    res.json({ success: true, users });
  } catch (error) {
    console.error("❌ Error fetching users:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/api/auth/profile", verifyToken, async (req, res) => {
  try {
    let user;
    
    if (req.userRole === "Admin") {
      user = await Admin.findById(req.userId, { password: 0 });
    } else {
      user = await User.findById(req.userId, { password: 0, verificationToken: 0 });
    }

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    res.json({
      success: true,
      user: {
        ...user.toObject(),
        role: req.userRole
      }
    });
  } catch (error) {
    console.error("❌ Error fetching profile:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

/* =======================
   Banner Routes (Animated Banners)
======================= */

// GET all active banners (for frontend)
app.get("/api/banners", async (req, res) => {
  try {
    const banners = await Banner.find({ isActive: true })
      .sort({ order: 1, createdAt: -1 });
    
    console.log(`📊 Fetched ${banners.length} active banners`);
    res.json({ success: true, banners });
  } catch (err) {
    console.error("❌ Error fetching banners:", err);
    res.status(500).json({ success: false, message: "حدث خطأ في جلب البانرات" });
  }
});

// GET all banners (for admin panel - now public)
app.get("/api/banners/all", async (req, res) => {
  try {
    const banners = await Banner.find()
      .sort({ order: 1, createdAt: -1 });
    
    console.log(`📊 Fetched ${banners.length} banners`);
    res.json({ success: true, banners });
  } catch (err) {
    console.error("❌ Error fetching all banners:", err);
    res.status(500).json({ success: false, message: "حدث خطأ في جلب البانرات" });
  }
});

// CREATE new banner (now public)
app.post("/api/banners", upload.single('image'), async (req, res) => {
  try {
    console.log("📝 Creating new banner");
    console.log("📦 Banner data:", req.body);
    console.log("🖼️ Banner file:", req.file ? `Present: ${req.file.filename}` : "None");

    if (!req.file) {
      return res.status(400).json({ success: false, message: "لم يتم رفع صورة البانر" });
    }

    const requiredFields = ['title', 'subtitle'];
    for (const field of requiredFields) {
      if (!req.body[field]) {
        // Delete uploaded file
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting uploaded file:", err);
        });
        return res.status(400).json({ 
          success: false, 
          message: `حقل ${field} مطلوب` 
        });
      }
    }

    // Count existing banners to set order
    const bannerCount = await Banner.countDocuments();
    
    const banner = new Banner({
      imageUrl: `/uploads/${req.file.filename}`,
      filename: req.file.filename,
      originalname: req.file.originalname,
      path: req.file.path,
      title: req.body.title,
      subtitle: req.body.subtitle,
      buttonText: req.body.buttonText || 'ابدأ الاستثمار الآن',
      buttonLink: req.body.buttonLink || '#register',
      secondaryButtonText: req.body.secondaryButtonText || 'اعرف المزيد',
      secondaryButtonLink: req.body.secondaryButtonLink || '#info',
      order: req.body.order || bannerCount,
      isActive: req.body.isActive !== 'false'
    });

    await banner.save();

    console.log("✅ Banner created successfully:", {
      id: banner._id,
      title: banner.title,
      imageUrl: banner.imageUrl
    });

    res.status(201).json({ 
      success: true, 
      message: 'تم إنشاء البانر بنجاح', 
      banner 
    });

  } catch (err) {
    console.error("❌ Error creating banner:", err);
    
    // Delete uploaded file if error
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error("Error deleting uploaded file:", err);
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: "حدث خطأ أثناء إنشاء البانر",
      error: err.message 
    });
  }
});

// UPDATE banner (now public)
app.put("/api/banners/:id", upload.single('image'), async (req, res) => {
  try {
    console.log(`📝 Updating banner: ${req.params.id}`);
    
    const banner = await Banner.findById(req.params.id);
    
    if (!banner) {
      if (req.file) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting uploaded file:", err);
        });
      }
      return res.status(404).json({ success: false, message: "البانر غير موجود" });
    }

    // Handle new image upload if provided
    if (req.file) {
      console.log("🖼️ New image uploaded, deleting old image");
      
      // Delete old image file
      if (banner.filename) {
        const oldImagePath = path.join(__dirname, '..', 'uploads', banner.filename);
        fs.unlink(oldImagePath, (err) => {
          if (err) console.error("Error deleting old image:", err);
        });
      }
      
      // Update with new image
      banner.imageUrl = `/uploads/${req.file.filename}`;
      banner.filename = req.file.filename;
      banner.originalname = req.file.originalname;
      banner.path = req.file.path;
    }

    // Update other fields
    if (req.body.title) banner.title = req.body.title;
    if (req.body.subtitle) banner.subtitle = req.body.subtitle;
    if (req.body.buttonText !== undefined) banner.buttonText = req.body.buttonText;
    if (req.body.buttonLink !== undefined) banner.buttonLink = req.body.buttonLink;
    if (req.body.secondaryButtonText !== undefined) banner.secondaryButtonText = req.body.secondaryButtonText;
    if (req.body.secondaryButtonLink !== undefined) banner.secondaryButtonLink = req.body.secondaryButtonLink;
    if (req.body.order !== undefined) banner.order = parseInt(req.body.order);
    if (req.body.isActive !== undefined) {
      banner.isActive = req.body.isActive === 'true' || req.body.isActive === true;
    }
    
    banner.updatedAt = new Date();

    await banner.save();

    console.log("✅ Banner updated successfully:", {
      id: banner._id,
      title: banner.title
    });

    res.json({ 
      success: true, 
      message: 'تم تحديث البانر بنجاح', 
      banner 
    });

  } catch (err) {
    console.error("❌ Error updating banner:", err);
    
    // Delete uploaded file if error
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error("Error deleting uploaded file:", err);
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: "حدث خطأ أثناء تحديث البانر",
      error: err.message 
    });
  }
});

// DELETE banner (now public)
app.delete("/api/banners/:id", async (req, res) => {
  try {
    console.log(`🗑️ Deleting banner: ${req.params.id}`);
    
    const banner = await Banner.findById(req.params.id);
    
    if (!banner) {
      return res.status(404).json({ success: false, message: "البانر غير موجود" });
    }

    // Delete image file
    if (banner.filename) {
      const imagePath = path.join(__dirname, '..', 'uploads', banner.filename);
      fs.unlink(imagePath, (err) => {
        if (err) console.error("Error deleting banner image:", err);
      });
    }

    await banner.deleteOne();

    console.log("✅ Banner deleted successfully:", req.params.id);

    res.json({ 
      success: true, 
      message: 'تم حذف البانر بنجاح' 
    });

  } catch (err) {
    console.error("❌ Error deleting banner:", err);
    res.status(500).json({ 
      success: false, 
      message: "حدث خطأ أثناء حذف البانر" 
    });
  }
});

// REORDER banners (now public)
app.post("/api/banners/reorder", async (req, res) => {
  try {
    const { banners } = req.body;
    
    if (!Array.isArray(banners)) {
      return res.status(400).json({ success: false, message: "بيانات غير صالحة" });
    }

    console.log("🔄 Reordering banners:", banners);

    for (const item of banners) {
      await Banner.findByIdAndUpdate(item.id, { order: item.order });
    }

    console.log("✅ Banners reordered successfully");

    res.json({ 
      success: true, 
      message: 'تم إعادة ترتيب البانرات بنجاح' 
    });

  } catch (err) {
    console.error("❌ Error reordering banners:", err);
    res.status(500).json({ 
      success: false, 
      message: "حدث خطأ أثناء إعادة ترتيب البانرات" 
    });
  }
});

// TOGGLE banner status (now public)
app.put("/api/banners/:id/toggle", async (req, res) => {
  try {
    const banner = await Banner.findById(req.params.id);
    
    if (!banner) {
      return res.status(404).json({ success: false, message: "البانر غير موجود" });
    }

    banner.isActive = !banner.isActive;
    banner.updatedAt = new Date();

    await banner.save();

    console.log(`✅ Banner ${banner.isActive ? 'activated' : 'deactivated'}:`, {
      id: banner._id,
      title: banner.title
    });

    res.json({ 
      success: true, 
      message: banner.isActive ? 'تم تفعيل البانر' : 'تم إلغاء تفعيل البانر',
      banner 
    });

  } catch (err) {
    console.error("❌ Error toggling banner status:", err);
    res.status(500).json({ 
      success: false, 
      message: "حدث خطأ أثناء تغيير حالة البانر" 
    });
  }
});

// GET banner statistics (now public)
app.get("/api/banners/stats", async (req, res) => {
  try {
    const totalBanners = await Banner.countDocuments();
    const activeBanners = await Banner.countDocuments({ isActive: true });
    const inactiveBanners = await Banner.countDocuments({ isActive: false });

    const stats = {
      totalBanners,
      activeBanners,
      inactiveBanners
    };

    console.log("📊 Banner stats:", stats);

    res.json({ 
      success: true, 
      stats 
    });

  } catch (err) {
    console.error("❌ Error fetching banner stats:", err);
    res.status(500).json({ 
      success: false, 
      message: "حدث خطأ في جلب إحصائيات البانرات" 
    });
  }
});
/* =======================
   Ads Routes (Advertisements)
======================= */



// GET all active ads (for frontend)
app.get("/api/ads", async (req, res) => {
  try {
    const ads = await Ad.find({ isActive: true })
      .sort({ order: 1, createdAt: -1 });
    
    console.log(`📊 Fetched ${ads.length} active ads`);
    
    // NO URL modification needed if ads already have full URLs
    res.json({ success: true, ads });
  } catch (err) {
    console.error("❌ Error fetching ads:", err);
    res.status(500).json({ success: false, message: "حدث خطأ في جلب الإعلانات" });
  }
});
// GET all ads (for admin panel)
app.get("/api/ads/all", async (req, res) => {
  try {
    const ads = await Ad.find()
      .sort({ order: 1, createdAt: -1 });
    
    console.log(`📊 Fetched ${ads.length} ads`);
    
    // Check what URLs are stored
    ads.forEach(ad => {
      console.log(`Ad ${ad._id} imageUrl:`, ad.imageUrl);
    });
    
    // IMPORTANT: If ads already have full URLs, DON'T add the base URL again
    // Only add base URL if it's a relative path
const adsWithFixedUrls = ads.map(ad => {
  const adObj = ad.toObject();
  
  // If imageUrl already starts with http, return as is
  if (adObj.imageUrl && (adObj.imageUrl.startsWith('http://') || adObj.imageUrl.startsWith('https://'))) {
    console.log(`Ad ${adObj._id} already has full URL: ${adObj.imageUrl}`);
    return adObj;
  }
  
  // If it's a relative path (starts with /uploads), add base URL
  if (adObj.imageUrl && adObj.imageUrl.startsWith('/uploads')) {
    const fullUrl = `${req.protocol}://${req.get('host')}${adObj.imageUrl}`;
    console.log(`Ad ${adObj._id} converting relative to full URL: ${fullUrl}`);
    return {
      ...adObj,
      imageUrl: fullUrl
    };
  }
  
  // Return as is for any other case
  return adObj;
});

res.json({ success: true, ads: adsWithFixedUrls });
} catch (err) {
console.error("❌ Error fetching all ads:", err);
res.status(500).json({ success: false, message: "حدث خطأ في جلب الإعلانات" });
}
});

// CREATE new ad
app.post("/api/ads", upload.single('image'), async (req, res) => {
  try {
    console.log("📝 Creating new ad");
    console.log("📦 Ad data:", req.body);
    console.log("🖼️ Ad file:", req.file ? `Present: ${req.file.filename}` : "None");

    if (!req.file) {
      return res.status(400).json({ success: false, message: "لم يتم رفع صورة الإعلان" });
    }

    if (!req.body.title || !req.body.description) {
      // Delete uploaded file
      fs.unlink(req.file.path, (err) => {
        if (err) console.error("Error deleting uploaded file:", err);
      });
      return res.status(400).json({ 
        success: false, 
        message: "العنوان والوصف مطلوبان" 
      });
    }

    // Count existing ads to set order
    const adCount = await Ad.countDocuments();
    
    // Create absolute URL for the image
    const imageUrl = `/uploads/${req.file.filename}`;
    const fullImageUrl = `${req.protocol}://${req.get('host')}${imageUrl}`;
    
    const ad = new Ad({
      imageUrl: fullImageUrl,
      relativeImageUrl: imageUrl,
      filename: req.file.filename,
      originalname: req.file.originalname,
      path: req.file.path,
      title: req.body.title,
      description: req.body.description,
      buttonText: req.body.buttonText || 'اعرف المزيد',
      buttonLink: req.body.buttonLink || '#',
      order: req.body.order || adCount,
      isActive: req.body.isActive !== 'false'
    });

    await ad.save();

    console.log("✅ Ad created successfully:", {
      id: ad._id,
      title: ad.title,
      imageUrl: ad.imageUrl
    });

    res.status(201).json({ 
      success: true, 
      message: 'تم إنشاء الإعلان بنجاح', 
      ad 
    });

  } catch (err) {
    console.error("❌ Error creating ad:", err);
    
    // Delete uploaded file if error
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error("Error deleting uploaded file:", err);
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: "حدث خطأ أثناء إنشاء الإعلان",
      error: err.message 
    });
  }
});

// UPDATE ad
app.put("/api/ads/:id", upload.single('image'), async (req, res) => {
  try {
    console.log(`📝 Updating ad: ${req.params.id}`);
    
    const ad = await Ad.findById(req.params.id);
    
    if (!ad) {
      if (req.file) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting uploaded file:", err);
        });
      }
      return res.status(404).json({ success: false, message: "الإعلان غير موجود" });
    }

    // Handle new image upload if provided
    if (req.file) {
      console.log("🖼️ New image uploaded, deleting old image");
      
      // Delete old image file
      if (ad.filename) {
        const oldImagePath = path.join(process.cwd(), 'uploads', ad.filename);
        fs.unlink(oldImagePath, (err) => {
          if (err) console.error("Error deleting old image:", err);
        });
      }
      
      // Create new absolute URL
      const imageUrl = `/uploads/${req.file.filename}`;
      const fullImageUrl = `${req.protocol}://${req.get('host')}${imageUrl}`;
      
      // Update with new image
      ad.imageUrl = fullImageUrl;
      ad.relativeImageUrl = imageUrl;
      ad.filename = req.file.filename;
      ad.originalname = req.file.originalname;
      ad.path = req.file.path;
    }

    // Update other fields
    if (req.body.title) ad.title = req.body.title;
    if (req.body.description) ad.description = req.body.description;
    if (req.body.buttonText !== undefined) ad.buttonText = req.body.buttonText;
    if (req.body.buttonLink !== undefined) ad.buttonLink = req.body.buttonLink;
    if (req.body.order !== undefined) ad.order = parseInt(req.body.order);
    if (req.body.isActive !== undefined) {
      ad.isActive = req.body.isActive === 'true' || req.body.isActive === true;
    }
    
    ad.updatedAt = new Date();

    await ad.save();

    console.log("✅ Ad updated successfully:", {
      id: ad._id,
      title: ad.title
    });

    res.json({ 
      success: true, 
      message: 'تم تحديث الإعلان بنجاح', 
      ad 
    });

  } catch (err) {
    console.error("❌ Error updating ad:", err);
    
    // Delete uploaded file if error
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error("Error deleting uploaded file:", err);
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: "حدث خطأ أثناء تحديث الإعلان",
      error: err.message 
    });
  }
});

// DELETE ad
app.delete("/api/ads/:id", async (req, res) => {
  try {
    console.log(`🗑️ Deleting ad: ${req.params.id}`);
    
    const ad = await Ad.findById(req.params.id);
    
    if (!ad) {
      return res.status(404).json({ success: false, message: "الإعلان غير موجود" });
    }

    // Delete image file
    if (ad.filename) {
      const imagePath = path.join(process.cwd(), 'uploads', ad.filename);
      fs.unlink(imagePath, (err) => {
        if (err) console.error("Error deleting ad image:", err);
      });
    }

    await ad.deleteOne();

    console.log("✅ Ad deleted successfully:", req.params.id);

    res.json({ 
      success: true, 
      message: 'تم حذف الإعلان بنجاح' 
    });

  } catch (err) {
    console.error("❌ Error deleting ad:", err);
    res.status(500).json({ 
      success: false, 
      message: "حدث خطأ أثناء حذف الإعلان" 
    });
  }
});

// GET ad statistics
app.get("/api/ads/stats", async (req, res) => {
  try {
    const totalAds = await Ad.countDocuments();
    const activeAds = await Ad.countDocuments({ isActive: true });
    const inactiveAds = await Ad.countDocuments({ isActive: false });

    const stats = {
      totalAds,
      activeAds,
      inactiveAds
    };

    console.log("📊 Ad stats:", stats);

    res.json({ 
      success: true, 
      stats 
    });

  } catch (err) {
    console.error("❌ Error fetching ad stats:", err);
    res.status(500).json({ 
      success: false, 
      message: "حدث خطأ في جلب إحصائيات الإعلانات" 
    });
  }
});


const footerSchema = new mongoose.Schema({
  companyName: { type: String, default: "منصتنا" },
  companyDescription: { type: String, default: "منصة رائدة للاستثمار والمشاريع الناشئة. نربط المستثمرين بالفرص الواعدة ونوفر بيئة آمنة وموثوقة للنمو والتطور." },
  email: { type: String, default: "info@platform.com" },
  phone: { type: String, default: "+213 XXX XXX XXX" },
  address: { type: String, default: "الوادي، الجزائر" },
  copyrightText: { type: String, default: "© 2025 Ashrik Maana" },
  
  // Social media links
  facebook: { type: String, default: "#" },
  twitter: { type: String, default: "#" },
  linkedin: { type: String, default: "#" },
  instagram: { type: String, default: "#" },
  
  // Toggle sections
  showQuickLinks: { type: Boolean, default: true },
  showContactInfo: { type: Boolean, default: true },
  showSocialMedia: { type: Boolean, default: true },
  showAdminAccess: { type: Boolean, default: true },
  
  // Quick links array
  quickLinks: [{
    name: String,
    url: String
  }]
}, {
  timestamps: true
});

// Ensure only one footer document exists
footerSchema.statics.getSingleton = async function() {
  let footer = await this.findOne();
  if (!footer) {
    footer = await this.create({});
  }
  return footer;
};


const Footer = mongoose.model('Footer', footerSchema);

// =======================
// Info Management Routes
// =======================

// Get all info
app.get('/api/info', async (req, res) => {
  try {
    console.log('GET /api/info - Fetching info data');
    
    let info = await Info.findOne();
    
    if (!info) {
      console.log('No info found, creating default');
      await Info.initInfo();
      info = await Info.findOne();
    }
    
    console.log('Info found:', info ? 'yes' : 'no');
    
    res.json({
      success: true,
      data: info
    });
  } catch (error) {
    console.error('❌ Error fetching info:', error);
    res.status(500).json({
      success: false,
      message: 'خطأ في جلب البيانات',
      error: error.message
    });
  }
});

// Helper function to process items array
const processSectionItems = (items) => {
  if (!items || !Array.isArray(items)) {
    return [];
  }
  
  return items.map((item, index) => {
    if (typeof item === 'string') {
      return {
        text: item,
        order: index + 1
      };
    }
    // If it's already an object but missing text
    if (item && typeof item === 'object' && !item.text && item.value) {
      return {
        text: item.value || item.text || '',
        order: item.order || index + 1
      };
    }
    // If it's already an object with text
    if (item && typeof item === 'object' && item.text) {
      return {
        text: item.text,
        order: item.order || index + 1
      };
    }
    // Return empty item if invalid
    return {
      text: '',
      order: index + 1
    };
  }).filter(item => item.text && item.text.trim() !== '');
};

// Update specific section
app.put('/api/info/:section', async (req, res) => {
  try {
    console.log(`PUT /api/info/${req.params.section} - Updating section`);
    
    const { section } = req.params;
    let updateData = req.body;
    
    // Validate section
    const validSections = ['about', 'contact', 'terms'];
    if (!validSections.includes(section)) {
      return res.status(400).json({
        success: false,
        message: 'القسم غير صحيح'
      });
    }
    
    // Find existing info or create new
    let info = await Info.findOne();
    if (!info) {
      console.log('No info found, creating default');
      await Info.initInfo();
      info = await Info.findOne();
    }
    
    console.log(`Updating section: ${section}`);
    
    // Process data based on section type
    if (section === 'terms' && updateData.sections) {
      // Process sections for terms
      updateData.sections = updateData.sections.map((sectionItem, index) => {
        const processedSection = {
          title: sectionItem.title || '',
          content: sectionItem.content || '',
          order: sectionItem.order || index + 1
        };
        
        // Process items if they exist
        if (sectionItem.items && Array.isArray(sectionItem.items)) {
          processedSection.items = processSectionItems(sectionItem.items);
        } else {
          processedSection.items = [];
        }
        
        return processedSection;
      });
    }
    
    // Update the specific section
    if (section === 'about') {
      info.about = {
        ...info.about,
        ...updateData,
        lastUpdated: Date.now()
      };
    } else if (section === 'contact') {
      info.contact = {
        ...info.contact,
        ...updateData,
        lastUpdated: Date.now()
      };
    } else if (section === 'terms') {
      info.terms = {
        ...info.terms,
        ...updateData,
        lastUpdatedDate: Date.now()
      };
      // Ensure lastUpdated has a value
      if (!info.terms.lastUpdated || info.terms.lastUpdated.trim() === '') {
        info.terms.lastUpdated = 'ديسمبر 2024';
      }
    }
    
    // Update main timestamp
    info.updatedAt = Date.now();
    
    // Save to database
    console.log('Saving to database...');
    await info.save();
    console.log('✅ Save successful');
    
    res.json({
      success: true,
      message: `تم تحديث ${section} بنجاح`,
      data: info
    });
  } catch (error) {
    console.error('❌ Error updating info:', error);
    res.status(500).json({
      success: false,
      message: 'خطأ في تحديث البيانات',
      error: error.message
    });
  }
});

// Update entire info document
app.put('/api/info', async (req, res) => {
  try {
    console.log('PUT /api/info - Updating all info');
    
    let updateData = req.body;
    
    // Process terms sections if they exist
    if (updateData.terms && updateData.terms.sections) {
      updateData.terms.sections = updateData.terms.sections.map((sectionItem, index) => {
        const processedSection = {
          title: sectionItem.title || '',
          content: sectionItem.content || '',
          order: sectionItem.order || index + 1
        };
        
        // Process items if they exist
        if (sectionItem.items && Array.isArray(sectionItem.items)) {
          processedSection.items = processSectionItems(sectionItem.items);
        } else {
          processedSection.items = [];
        }
        
        return processedSection;
      });
    }
    
    let info = await Info.findOne();
    if (!info) {
      console.log('Creating new info document');
      // Create new document with processed data
      info = new Info({
        about: {
          title: updateData.about?.title || 'عن منصة أشرك معنا',
          description: updateData.about?.description || '',
          services: updateData.about?.services || [],
          vision: updateData.about?.vision || '',
          mission: updateData.about?.mission || '',
          lastUpdated: Date.now()
        },
        contact: {
          title: updateData.contact?.title || 'تواصل معنا',
          address: updateData.contact?.address || '',
          phone: updateData.contact?.phone || [],
          email: updateData.contact?.email || [],
          workingHours: updateData.contact?.workingHours || '',
          socialMedia: updateData.contact?.socialMedia || [],
          lastUpdated: Date.now()
        },
        terms: {
          title: updateData.terms?.title || 'شروط وأحكام الاستخدام',
          lastUpdated: updateData.terms?.lastUpdated || 'ديسمبر 2024',
          sections: updateData.terms?.sections || [],
          lastUpdatedDate: Date.now()
        },
        createdAt: Date.now(),
        updatedAt: Date.now()
      });
    } else {
      console.log('Updating existing info document');
      
      // Update about section
      if (updateData.about) {
        info.about = {
          ...info.about,
          ...updateData.about,
          lastUpdated: Date.now()
        };
      }
      
      // Update contact section
      if (updateData.contact) {
        info.contact = {
          ...info.contact,
          ...updateData.contact,
          lastUpdated: Date.now()
        };
      }
      
      // Update terms section
      if (updateData.terms) {
        info.terms = {
          ...info.terms,
          ...updateData.terms,
          lastUpdatedDate: Date.now()
        };
        
        // Ensure lastUpdated has a value
        if (!info.terms.lastUpdated || info.terms.lastUpdated.trim() === '') {
          info.terms.lastUpdated = 'ديسمبر 2024';
        }
      }
      
      info.updatedAt = Date.now();
    }
    
    console.log('Saving to database...');
    await info.save();
    console.log('✅ Save successful');
    
    res.json({
      success: true,
      message: 'تم تحديث جميع البيانات بنجاح',
      data: info
    });
  } catch (error) {
    console.error('❌ Error updating all info:', error);
    res.status(500).json({
      success: false,
      message: 'خطأ في تحديث البيانات',
      error: error.message
    });
  }
});

// =======================
// Mongoose Schemas (Simplified)
// =======================

const serviceSchema = new mongoose.Schema({
  title: {
    type: String,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  icon: {
    type: String,
    default: 'money',
    enum: ['money', 'secure', 'tracking', 'support', 'vision', 'mission', 'building']
  },
  order: {
    type: Number,
    default: 0
  }
}, { _id: true });

const socialMediaSchema = new mongoose.Schema({
  platform: {
    type: String,
    default: 'whatsapp',
    enum: ['whatsapp', 'facebook', 'twitter', 'linkedin', 'instagram', 'youtube', 'telegram']
  },
  name: {
    type: String,
    trim: true
  },
  url: {
    type: String,
    trim: true
  },
  icon: {
    type: String,
    default: ''
  },
  order: {
    type: Number,
    default: 0
  }
}, { _id: true });

// Simplified section item schema that accepts strings
const sectionItemSchema = new mongoose.Schema({
  text: {
    type: String,
    trim: true,
    default: ''
  },
  order: {
    type: Number,
    default: 0
  }
}, { 
  _id: false,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Make text field more flexible
sectionItemSchema.set('strict', false);

const sectionSchema = new mongoose.Schema({
  title: {
    type: String,
    trim: true,
    default: ''
  },
  content: {
    type: String,
    trim: true,
    default: ''
  },
  items: [sectionItemSchema],
  order: {
    type: Number,
    default: 0
  }
}, { 
  _id: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Make items field more flexible
sectionSchema.path('items').schema.set('strict', false);

const aboutSchema = new mongoose.Schema({
  title: {
    type: String,
    trim: true,
    default: 'عن منصة أشرك معنا'
  },
  description: {
    type: String,
    trim: true,
    default: ''
  },
  services: [serviceSchema],
  vision: {
    type: String,
    trim: true,
    default: ''
  },
  mission: {
    type: String,
    trim: true,
    default: ''
  },
  lastUpdated: {
    type: Date,
    default: Date.now
  }
}, { 
  _id: false,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

const contactSchema = new mongoose.Schema({
  title: {
    type: String,
    trim: true,
    default: 'تواصل معنا'
  },
  address: {
    type: String,
    trim: true,
    default: ''
  },
  phone: [{
    type: String,
    trim: true
  }],
  email: [{
    type: String,
    trim: true
  }],
  workingHours: {
    type: String,
    trim: true,
    default: ''
  },
  socialMedia: [socialMediaSchema],
  lastUpdated: {
    type: Date,
    default: Date.now
  }
}, { 
  _id: false,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

const termsSchema = new mongoose.Schema({
  title: {
    type: String,
    trim: true,
    default: 'شروط وأحكام الاستخدام'
  },
  lastUpdated: {
    type: String,
    trim: true,
    default: 'ديسمبر 2024'
  },
  sections: [sectionSchema],
  lastUpdatedDate: {
    type: Date,
    default: Date.now
  }
}, { 
  _id: false,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

const infoSchema = new mongoose.Schema({
  about: {
    type: aboutSchema,
    default: () => ({})
  },
  contact: {
    type: contactSchema,
    default: () => ({})
  },
  terms: {
    type: termsSchema,
    default: () => ({})
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Make schemas more flexible to avoid validation errors
infoSchema.set('strict', false);
aboutSchema.set('strict', false);
contactSchema.set('strict', false);
termsSchema.set('strict', false);

// Create a single document with default data if not exists
infoSchema.statics.initInfo = async function() {
  try {
    const count = await this.countDocuments();
    if (count === 0) {
      console.log('Creating default info document...');
      
      const defaultInfo = new this({
        about: {
          title: 'عن منصة أشرك معنا',
          description: 'منصة أشرك معنا هي منصة رائدة في مجال الاستثمار التساهمي في الجزائر، حيث نربط بين أصحاب المشاريع الواعدة والمستثمرين الذين يبحثون عن فرص استثمارية مجزية. نهدف إلى تعزيز ثقافة الاستثمار المشترك وبناء اقتصاد قوي يعتمد على التعاون والشفافية.',
          services: [
            {
              title: 'فرص استثمارية متنوعة',
              description: 'نوفر مجموعة واسعة من المشاريع في مختلف القطاعات للاستثمار فيها بكل ثقة وشفافية.',
              icon: 'money',
              order: 1
            },
            {
              title: 'تمويل آمن وموثوق',
              description: 'نضمن عمليات تمويل آمنة ومراقبة بدقة لحماية حقوق جميع الأطراف.',
              icon: 'secure',
              order: 2
            },
            {
              title: 'تتبع دقيق للاستثمارات',
              description: 'لوحة تحكم متطورة تتيح لك متابعة استثماراتك وعوائدها بشكل لحظي.',
              icon: 'tracking',
              order: 3
            },
            {
              title: 'دعم فني متواصل',
              description: 'فريق دعم محترف متاح على مدار الساعة لمساعدتك في أي استفسار.',
              icon: 'support',
              order: 4
            }
          ],
          vision: 'أن نكون المنصة الرائدة في الجزائر والمنطقة العربية للاستثمار التساهمي، ونساهم في بناء اقتصاد قوي يعتمد على التعاون والشراكة.',
          mission: 'توفير منصة آمنة وشفافة تربط المستثمرين بأصحاب المشاريع، وتساعد على تحقيق النمو الاقتصادي من خلال الاستثمار المسؤول.',
          lastUpdated: Date.now()
        },
        contact: {
          title: 'تواصل معنا',
          address: 'الجزائر العاصمة، حي الأعمال\nالطابق 5، برج النور\nالجزائر 16000',
          phone: ['+213 555 123 456', '+213 555 789 012'],
          email: ['info@ashrakmana.dz', 'support@ashrakmana.dz'],
          workingHours: 'الأحد - الخميس\nمن 9:00 صباحاً - 6:00 مساءً\nالدعم الفني متاح 24/7',
          socialMedia: [
            {
              platform: 'whatsapp',
              name: 'واتساب',
              url: 'https://whatsapp.com/ashrakmana',
              icon: 'whatsapp',
              order: 1
            },
            {
              platform: 'facebook',
              name: 'فيسبوك',
              url: 'https://facebook.com/ashrakmana',
              icon: 'facebook',
              order: 2
            },
            {
              platform: 'twitter',
              name: 'تويتر',
              url: 'https://twitter.com/ashrakmana',
              icon: 'twitter',
              order: 3
            }
          ],
          lastUpdated: Date.now()
        },
        terms: {
          title: 'شروط وأحكام الاستخدام',
          lastUpdated: 'ديسمبر 2024',
          sections: [
            {
              title: 'القبول والموافقة',
              content: 'باستخدامك لمنصة أشرك معنا، فإنك توافق على الالتزام بهذه الشروط والأحكام. إذا كنت لا توافق على أي من هذه الشروط، يرجى عدم استخدام المنصة. نحتفظ بالحق في تعديل هذه الشروط في أي وقت، وسيتم إخطارك بأي تغييرات جوهرية.',
              items: [],
              order: 1
            },
            {
              title: 'التسجيل والحساب',
              content: 'متطلبات التسجيل واستخدام الحساب:',
              items: [
                { text: 'يجب أن تكون بعمر 18 عاماً على الأقل للتسجيل في المنصة', order: 1 },
                { text: 'يجب تقديم معلومات دقيقة وصحيحة عند التسجيل', order: 2 },
                { text: 'أنت مسؤول عن الحفاظ على سرية بيانات حسابك', order: 3 },
                { text: 'يحق لنا تعليق أو إلغاء حسابك في حالة انتهاك الشروط', order: 4 }
              ],
              order: 2
            }
          ],
          lastUpdatedDate: Date.now()
        },
        createdAt: Date.now(),
        updatedAt: Date.now()
      });
      
      await defaultInfo.save();
      console.log('✅ Default info document created successfully');
      return defaultInfo;
    } else {
      console.log('ℹ️ Info document already exists');
      return await this.findOne();
    }
  } catch (error) {
    console.error('❌ Error in initInfo:', error);
    throw error;
  }
};

const Info = mongoose.model('Info', infoSchema);





/* =======================
   Start Server
======================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
