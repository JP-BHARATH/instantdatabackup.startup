// server.js
import { fileURLToPath } from 'url';
import { dirname } from 'path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
import 'dotenv/config'; // This should always be at the very top to load .env variables
import express from 'express';
import connectDB from './config/db.js';
import User from './models/User.js'; // Ensure this path is correct
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
// import auth from './middleware/auth.js'; // Original auth middleware, using custom one below
import multer from 'multer';
import path from 'path';
import fsp from 'fs/promises'; // For promise-based file system operations
import fs from 'fs'; // For synchronous file system operations (e.g., existsSync)
import crypto from 'crypto'; // For cryptographic operations like generating tokens
import archiver from 'archiver';
import { Block, Blockchain } from './lib/blockchain.js'; // Ensure this is only imported once at the top
import BlockchainState from './models/BlockchainState.js'; // Import your BlockchainState model
import cors from 'cors';
import helmet from 'helmet';
import { check, validationResult } from 'express-validator';
import rateLimit from 'express-rate-limit';
import mime from 'mime-types'; // <--- ADDED THIS IMPORT for MIME type detection
import { v4 as uuidv4 } from 'uuid'; // For unique serial numbers
import Activity from './models/Activity.js'; // Adjust path as needed, add .js extension
import Issue from './models/Issue.js';// Adjust path as needed, add .js extension (using Issue for feedback)
import { sendEmail } from './utils/emailSender.js';
import File from './models/File.js'; // Import your File model
import profileRoutes from './routes/profileRoutes.js';
import Feedback from './models/Feedback.js';

const app = express();
const port = 3000;

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY) {
console.error("CRITICAL ERROR: ENCRYPTION_KEY is not set in environment variables. Please set it in your .env file or server environment.");
process.exit(1);
}
const IV_LENGTH = 16;

// --- JWT Configuration ---
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
console.error("CRITICAL ERROR: JWT_SECRET is not set in environment variables. Please set it in your .env file or server environment.");
process.exit(1);
}

// Declare instantDataBackupChain globally so it can be accessed by routes
let instantDataBackupChain;

// --- Initialize and Load Blockchain from Database ---
async function initializeBlockchain() {
try {
let blockchainState = await BlockchainState.findOne({});

if (!blockchainState) {
instantDataBackupChain = new Blockchain();
blockchainState = new BlockchainState({
chain: instantDataBackupChain.chain.map(block => ({
index: block.index,
timestamp: block.timestamp,
data: block.data,
reviousHash: block.previousHash,
hasher: block.hasher,
nonce: block.nonce
})),
difficulty: instantDataBackupChain.difficulty
});
await blockchainState.save();
console.log("No existing blockchain found in DB. Created new Genesis Block and saved to DB.");
    } else {
      instantDataBackupChain = new Blockchain(blockchainState.chain, blockchainState.difficulty);
      console.log(`Blockchain loaded with ${instantDataBackupChain.chain.length} blocks from DB.`);
    }

    if (!instantDataBackupChain.isChainValid()) {
      console.error("Warning: Loaded blockchain is not valid! Potential data corruption or tampering detected.");
      // OPTIONAL: Implement recovery or alert mechanism here
    }

  } catch (error) {
    console.error("Critical Error: Failed to initialize or load blockchain from database:", error);
    process.exit(1);
  }
}

// --- Connect to MongoDB ---
connectDB();

// --- Middleware ---
app.use(express.json()); // To parse JSON bodies
app.use(express.urlencoded({ extended: true })); // To parse URL-encoded bodies (for simple form data)

// --- Strict CORS Configuration ---
app.use(cors({
  origin: 'https://3000-firebase-instant-data-backup-1748249505922.cluster-nzwlpk54dvagsxetkvxzbvslyi.cloudworkstations.dev',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));

// --- Security Headers with Helmet ---
app.use(helmet());

// --- Rate Limiting Configuration ---
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { message: 'Too many authentication attempts from this IP, please try again after 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 500,
  message: { message: 'Too many requests from this IP, please try again after an hour.' },
  standardHeaders: true,
  legacyHeaders: false,
});
// --- End Rate Limiting Configuration ---

// --- Multer Configuration for File Uploads ---
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    fs.mkdirSync('uploads/', { recursive: true });
    cb(null, 'uploads/');
  },
  filename: function(req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 100000000 }, // 100 MB limit
  fileFilter: function(req, file, cb) {
    checkFileType(file, cb);
  }
});

// Multer for handling simple form data (like feedback form) without file uploads
const formParser = multer();

function checkFileType(file, cb) {
  const allowedMimeTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt|zip|rar|mp4|mov|avi|mp3|wav|json|xml|csv/;
  const extname = allowedMimeTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedMimeTypes.test(file.mimetype) || file.mimetype.startsWith('text/') || file.mimetype.startsWith('application/');

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb('Error: Files of this type are not supported! Allowed: images, pdf, documents, text, archives, common video/audio.');
  }
}
// --- End Multer Configuration ---

// --- Encryption/Decryption Helper Functions ---
function encrypt(buffer) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(buffer);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(encryptedText) {
  const textParts = encryptedText.split(':');
  const iv = Buffer.from(textParts.shift(), 'hex');
  const encryptedData = Buffer.from(textParts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let decrypted = decipher.update(encryptedData);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted;
}
// --- End Encryption/Decryption Helper Functions ---

// --- Custom Authentication Middleware ---
// This middleware is designed to extract userId, username, and serialNumber from the JWT
const authMiddleware = (req, res, next) => {
  // Get token from header
  const authHeader = req.header('Authorization');

  // Check if not token or not in Bearer format
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.log("DEBUG AUTH: No Bearer token found in Authorization header.");
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  const token = authHeader.split(' ')[1]; // Extract the token part

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET); 
    
    console.log("DEBUG AUTH: Token decoded successfully.");
    console.log("DEBUG AUTH: Decoded payload:", decoded);
    
    // Ensure that decoded.user contains the necessary properties
    if (!decoded.user) {
      console.error("DEBUG AUTH ERROR: Decoded token missing 'user' property.");
      return res.status(401).json({ message: 'Token invalid: User data missing.' });
    }
    
    req.user = decoded.user; // This is where req.user is populated
    
    console.log("DEBUG AUTH: req.user populated:", req.user);
    
    next(); // Proceed to the next middleware/route handler
  } catch (err) {
    console.error("DEBUG AUTH ERROR: Token verification failed:", err.message);
    res.status(401).json({ message: 'Token is not valid' });
  }
};

// --- End Custom Authentication Middleware ---


// Serve static files from the 'frontend' directory
app.use(express.static(path.join(__dirname, 'frontend')));

// --- API Routes ---

// --- Consolidated User Registration Endpoint (/api/register) ---
app.post(
  '/api/register',
  authLimiter,
  [
    check('username', 'Username is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password must be 6 or more characters').isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }

    const { username, email, password } = req.body;

    try {
      console.log('Register - received email:', email);
      console.log('Register - received username:', username);

      let user = await User.findOne({ email });
      if (user) {
        return res.status(400).json({ message: 'User already exists' });
      }

      const serialNumber = uuidv4();

      user = new User({
        username,
        email,
        password: password, // The pre-save hook will hash this
        serial_number: serialNumber,
        total_storage_used: 0,
        last_login: new Date(),
        name: username // Optionally keep for compatibility
      });

      await user.save();
      console.log('Register - User saved successfully to DB.');

      const payload = {
        user: {
          id: user.id,
          userId: user._id,
          username: user.username,
          email: user.email, // Include email in payload for profile page
          serialNumber: user.serial_number,
        },
      };

      jwt.sign(
        payload,
        JWT_SECRET,
        { expiresIn: '1h' },
        (err, token) => {
          if (err) {
            console.error('JWT Sign Error:', err);
            throw err;
          }
          res.status(201).json({ message: 'User registered successfully', token, username: user.username });
        }
      );
    } catch (err) {
      console.error('Registration Error:', err.message);
      res.status(500).send('Server error during registration');
    }
  }
);

// --- Consolidated User Login Endpoint (/api/login) ---
app.post(
  '/api/login',
  authLimiter,
  [
    check('password', 'Password is required').exists(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: errors.array()[0].msg });
    }

    const { username, email, password } = req.body;

    try {
      console.log('Login - received username:', username, 'email:', email);

      let user;
      if (email && email.length > 0) {
        user = await User.findOne({ email });
        console.log('Login - Attempting to find user by email:', email);
      } else if (username && username.length > 0) {
        user = await User.findOne({ username });
        console.log('Login - Attempting to find user by username:', username);
      } else {
        return res.status(400).json({ message: 'Please enter your email or username.' });
      }

      if (!user) {
        console.log('Login - User not found for provided credentials.');
        return res.status(400).json({ message: 'Invalid credentials' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      console.log('Login - bcrypt.compare result (true/false):', isMatch);
      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid credentials' });
      }

      // Update last_login on successful login
      user.last_login = new Date();
      await user.save();

      // Log the login activity
      const loginActivity = new Activity({
        user_id: user._id,
        timestamp: new Date(),
        action: 'login',
        description: `User ${user.username || user.email} logged in.`,
      });
      await loginActivity.save();

      const payload = {
        user: {
          id: user.id,
          userId: user._id,
          username: user.username,
          email: user.email,
          // encryptionKey: user.encryptionKey // Only include if user-specific encryption is implemented
        },
      };

      jwt.sign(
        payload,
        JWT_SECRET,
        { expiresIn: '1h' },
        (err, token) => {
          if (err) {
            console.error('JWT Sign Error:', err);
            return res.status(500).json({ message: 'Token generation failed.' });
          }
          res.json({ message: 'Logged in successfully', token, username: user.username });
        }
      );
    } catch (err) {
      console.error('Login Error:', err.message);
      res.status(500).send('Server error during login');
    }
  }
);


// Request OTP for password reset
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    // 1. Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(200).json({ 
        success: true,
        message: 'If an account exists with this email, an OTP has been sent'
      });
    }

    // 2. Generate OTP (6-digit number)
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpire = Date.now() + 15 * 60 * 1000; // 15 minutes expiry

    // 3. Save OTP to user
    user.resetPasswordOtp = otp;
    user.resetPasswordOtpExpire = otpExpire;
    await user.save();

    // 4. Send email with OTP
    const emailResult = await sendEmail(
      user.email,
      'Password Reset OTP',
      `Your OTP for password reset is: ${otp}`,
      `<p>Your OTP for password reset is: <strong>${otp}</strong></p>
       <p>This OTP is valid for 15 minutes.</p>`
    );

    if (!emailResult.success) {
      console.error('Failed to send OTP email:', emailResult.error);
      return res.status(500).json({ 
        success: false,
        message: 'Failed to send OTP email'
      });
    }

    res.status(200).json({ 
      success: true,
      message: 'OTP sent to email'
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error'
    });
  }
});

// Verify OTP and allow password reset
app.post('/api/auth/verify-reset-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    // 1. Find user by email
    const user = await User.findOne({ 
      email,
      resetPasswordOtpExpire: { $gt: Date.now() }
    });
    
    if (!user || user.resetPasswordOtp !== otp) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid or expired OTP'
      });
    }

    // 2. Generate reset token (for the frontend to use)
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetExpire = Date.now() + 30 * 60 * 1000; // 30 minutes expiry

    // 3. Save reset token to user
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpire = resetExpire;
    user.resetPasswordOtp = undefined;
    user.resetPasswordOtpExpire = undefined;
    await user.save();

    res.status(200).json({ 
      success: true,
      message: 'OTP verified',
      resetToken
    });
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error'
    });
  }
});

// Reset password with valid token
app.put('/api/auth/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    
    // 1. Find user by valid reset token
    const user = await User.findOne({
      resetPasswordToken: resetToken,
      resetPasswordExpire: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid or expired token'
      });
    }

    // 2. Update password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    
    // 3. Clear reset token
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    
    await user.save();

    res.status(200).json({ 
      success: true,
      message: 'Password updated successfully'
    });
  } catch (error) {
    console.error('Password reset error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Server error'
    });
  }
});


// --- API for User Feedback/Bug Report ---
// Use formParser.none() to handle FormData for text fields
// Submit feedback
app.post('/api/profile/feedback', authMiddleware, express.json(), async (req, res) => {
    try {
        const { subject, description } = req.body;
        const user = await User.findById(req.user.userId);
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const newFeedback = new Feedback({
            user: req.user.userId,
            username: user.username,
            email: user.email,
            subject,
            description,
            status: 'open'
        });

        await newFeedback.save();
        
        // Log activity with valid action type
        await new Activity({
            user_id: req.user.userId,
            action: 'feedback_submitted', // Now this is valid
            description: `Submitted feedback: "${subject.substring(0, 50)}..."`
        }).save();

        res.status(201).json({ 
            message: 'Feedback submitted successfully',
            feedback: newFeedback
        });
    } catch (err) {
        console.error('Error submitting feedback:', err.message);
        res.status(500).json({ message: 'Server Error', error: err.message });
    }
});

// Get user's feedback
app.get('/api/profile/feedback', authMiddleware, async (req, res) => {
    try {
        const feedbacks = await Feedback.find({ user: req.user.userId })
            .sort({ createdAt: -1 });
        res.json(feedbacks);
    } catch (err) {
        console.error('Error fetching feedback:', err.message);
        res.status(500).json({ message: 'Server Error', error: err.message });
    }
});

// File Upload, Encryption, Local Storage, and Blockchain Integration
app.post('/api/upload', authMiddleware, apiLimiter, upload.array('file'), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ message: 'No files uploaded.' });
    }

    if (!req.user || (req.user.userId === undefined && req.user.id === undefined)) {
      console.error("Authentication Error: req.user or user ID (userId/id) is missing in /api/upload.");
      return res.status(401).json({ message: 'Unauthorized: User information missing from token.' });
    }
    const userId = req.user.userId || req.user.id;
    if (!userId) {
      console.error("CRITICAL ERROR: userId variable is undefined despite token validation in /api/upload.");
      return res.status(500).json({ message: 'Server configuration error: User ID could not be determined.' });
    }
    console.log("DEBUG: Uploading for userId:", userId);

    const encryptedDir = 'encrypted_files';
    await fsp.mkdir(encryptedDir, { recursive: true });

    const uploadedFilesResponse = [];
    let totalUploadedSize = 0;

    for (const file of req.files) {
      const originalFilePath = file.path;
      const originalFileName = file.originalname;

      try {
        const fileBuffer = await fsp.readFile(originalFilePath);
        const encryptedContentHex = encrypt(fileBuffer);

        const encryptedFileNameOnDisk = `${crypto.randomBytes(16).toString('hex')}.enc`;
        const encryptedFilePath = path.join(encryptedDir, encryptedFileNameOnDisk);
        await fsp.writeFile(encryptedFilePath, encryptedContentHex);

        const encryptedFileHash = crypto.createHash('sha256').update(encryptedContentHex).digest('hex');

        await fsp.unlink(originalFilePath);

        const fileMetadata = {
          originalName: originalFileName,
          mimeType: file.mimetype,
          encryptedFileName: encryptedFileNameOnDisk,
          fileSize: file.size,
          encryptedFileHash: encryptedFileHash,
          uploadDate: new Date().toISOString(),
          userId: userId
        };

        const newFileRecord = new File(fileMetadata);
        await newFileRecord.save();

        const latestBlock = instantDataBackupChain.getLatestBlock();
        const newBlock = new Block(
          instantDataBackupChain.chain.length,
          Date.now(),
          {
            type: 'file_upload',
            userId: userId,
            originalName: fileMetadata.originalName,
            encryptedFileName: fileMetadata.encryptedFileName,
            fileSize: fileMetadata.fileSize,
            mimeType: fileMetadata.mimeType,
            encryptedFileHash: encryptedFileHash
          },
          latestBlock.hasher
        );
        instantDataBackupChain.addBlock(newBlock);
        console.log(`Block mined: ${newBlock.hasher}`);
        console.log(`New block added to the blockchain: ${newBlock.hasher}`);

        totalUploadedSize += file.size;

        const uploadActivity = new Activity({
          user_id: userId,
          timestamp: new Date(),
          action: 'upload',
          file_name: file.originalname,
          file_size: file.size,
          description: `Uploaded file: ${file.originalname}`
        });
        await uploadActivity.save();

        uploadedFilesResponse.push({
          originalName: originalFileName,
          mimeType: file.mimetype,
          encryptedFileName: encryptedFileNameOnDisk,
          fileSize: file.size,
          blockchainHash: newBlock.hasher
        });

      } catch (fileError) {
        console.error(`Error processing file ${originalFileName}:`, fileError);
        if (originalFilePath && fs.existsSync(originalFilePath)) {
          await fsp.unlink(originalFilePath).catch(e => console.error(`Failed to delete temp file ${originalFilePath} during error cleanup:`, e));
        }
      }
    }

    if (instantDataBackupChain.isChainValid()) {
      console.log('Is chain valid? true');
      const blockchainState = await BlockchainState.findOne({});
      if (blockchainState) {
        blockchainState.chain = instantDataBackupChain.chain.map(block => ({
          index: block.index,
          timestamp: block.timestamp,
          data: block.data,
          previousHash: block.previousHash,
          hasher: block.hasher,
          nonce: block.nonce
        }));
        blockchainState.difficulty = instantDataBackupChain.difficulty;
        await blockchainState.save();
        console.log("Blockchain state updated and saved to DB.");
      } else {
        console.error("Error: Blockchain state document not found after initialization. Creating new one as fallback.");
        const newBlockchainState = new BlockchainState({
          chain: instantDataBackupChain.chain.map(block => ({
            index: block.index,
            timestamp: block.timestamp,
            data: block.data,
            previousHash: block.previousHash,
            hasher: block.hasher,
            nonce: block.nonce
          })),
          difficulty: instantDataBackupChain.difficulty
        });
        await newBlockchainState.save();
      }
    } else {
      console.error('Is chain valid? false - Chain integrity compromised after upload!');
      return res.status(500).json({ message: 'Blockchain integrity compromised during upload process.' });
    }

    if (totalUploadedSize > 0) {
      await User.findByIdAndUpdate(userId, { $inc: { total_storage_used: totalUploadedSize } });
    }

    res.status(200).json({
      message: `${uploadedFilesResponse.length} file(s) uploaded, encrypted, stored locally, and metadata added to blockchain!`,
      uploadedFiles: uploadedFilesResponse
    });

  } catch (error) {
    console.error('Overall File Upload/Encryption/Blockchain Error:', error);
    if (error instanceof multer.MulterError) {
      return res.status(400).json({ message: `Upload error: ${error.message}` });
    }
    res.status(500).json({ message: 'Server error during file upload and encryption.' });
  }
});

// Endpoint to view the entire Blockchain (can be public or protected)
app.get('/api/blockchain', async (req, res) => {
  try {
    const blockchainState = await BlockchainState.findOne({});
    if (blockchainState) {
      const loadedChainInstance = new Blockchain(blockchainState.chain, blockchainState.difficulty);
      res.status(200).json({
        chain: blockchainState.chain,
        isValid: loadedChainInstance.isChainValid(),
        totalBlocks: blockchainState.chain.length
      });
    } else {
      res.status(404).json({ message: "Blockchain not found or not initialized." });
    }
  } catch (error) {
    console.error("Error fetching blockchain:", error);
    res.status(500).json({ message: "Server error fetching blockchain." });
  }
});

// NEW: File Restore Endpoint (protected by authMiddleware and includes user ID check)
app.get('/api/restore/:encryptedFileName', authMiddleware, apiLimiter, async (req, res) => {
  const requestedEncryptedFileName = req.params.encryptedFileName;
  const encryptedDir = 'encrypted_files';

  try {
    const blockchainState = await BlockchainState.findOne({});
    if (!blockchainState || !blockchainState.chain || blockchainState.chain.length === 0) {
      return res.status(404).json({ message: "Blockchain is empty or not initialized. No files to restore." });
    }

    const currentBlockchain = new Blockchain(blockchainState.chain, blockchainState.difficulty);

    let fileMetadata = null;
    for (let i = currentBlockchain.chain.length - 1; i >= 0; i--) {
      const block = currentBlockchain.chain[i];
      if (block.data && typeof block.data === 'object' && block.data.encryptedFileName === requestedEncryptedFileName) {
        fileMetadata = block.data;
        break;
      }
    }

    if (!fileMetadata) {
      return res.status(404).json({ message: "File metadata not found on the blockchain." });
    }

    if (fileMetadata.userId && fileMetadata.userId.toString() !== req.user.userId.toString()) {
      console.warn(`Unauthorized restore attempt: User ${req.user.userId} tried to restore file belonging to ${fileMetadata.userId}`);
      return res.status(403).json({ message: 'Unauthorized: You can only restore your own files.' });
    }

    if (fileMetadata.status === 'deleted') {
      return res.status(400).json({ message: 'File is marked as deleted on the blockchain and cannot be restored. Please contact support if you need to recover it.' });
    }

    const encryptedFilePath = path.join(encryptedDir, fileMetadata.encryptedFileName);

    if (!fs.existsSync(encryptedFilePath)) {
      console.warn(`Encrypted file missing from disk: ${encryptedFilePath}. Metadata exists on blockchain.`);
      return res.status(404).json({ message: "Encrypted file not found on server disk, although metadata exists on blockchain. It might have been deleted or moved." });
    }

    const encryptedContentHex = await fsp.readFile(encryptedFilePath, 'utf8');
    const decryptedBuffer = decrypt(encryptedContentHex);

    const contentType = fileMetadata.mimeType || mime.lookup(fileMetadata.originalName) || 'application/octet-stream';
    console.log(`Restoring file '${fileMetadata.originalName}' with Content-Type: ${contentType}`);

    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `inline; filename="${fileMetadata.originalName}"`);
    res.setHeader('Content-Length', decryptedBuffer.length);
    res.status(200).send(decryptedBuffer);

    console.log(`File '${fileMetadata.originalName}' restored successfully.`);

    const downloadActivity = new Activity({
      user_id: req.user.userId,
      timestamp: new Date(),
      action: 'download',
      file_name: fileMetadata.originalName,
      description: `Downloaded file: ${fileMetadata.originalName}`
    });
    await downloadActivity.save();

  } catch (error) {
    console.error('File Restore Error:', error);
    res.status(500).json({ message: 'Server error during file restore', error: error.message });
  }
});

// NEW: User-Specific File Listing
app.get('/api/user/files', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const userId = req.user.userId;

    const blockchainState = await BlockchainState.findOne({});
    if (!blockchainState || !blockchainState.chain || blockchainState.chain.length === 0) {
      return res.status(200).json({ files: [], message: "No files found for this user or blockchain is empty." });
    }

    const currentBlockchain = new Blockchain(blockchainState.chain, blockchainState.difficulty);

    const fileStatuses = new Map();

    for (let i = currentBlockchain.chain.length - 1; i >= 0; i--) {
      const block = currentBlockchain.chain[i];
      if (block.data && typeof block.data === 'object' && block.data.userId && block.data.encryptedFileName) {
        if (block.data.userId.toString() === userId.toString()) {
          const encryptedFileName = block.data.encryptedFileName;
          if (encryptedFileName && !fileStatuses.has(encryptedFileName)) {
            fileStatuses.set(encryptedFileName, { blockData: block.data, isDeleted: block.data.status === 'deleted' });
          }
        }
      }
    }

    const activeFiles = Array.from(fileStatuses.values())
                .filter(({ isDeleted }) => !isDeleted)
                .map(({ blockData }) => ({
                  originalName: blockData.originalName,
                  encryptedFileName: blockData.encryptedFileName,
                  fileSize: blockData.fileSize,
                  uploadDate: blockData.uploadDate,
                  blockchainHash: blockData.hasher,
                  mimeType: blockData.mimeType
                }));

    activeFiles.sort((a, b) => new Date(b.uploadDate) - new Date(a.uploadDate));

    res.status(200).json({
      files: activeFiles,
      totalFiles: activeFiles.length,
      message: `Found ${activeFiles.length} active files for user ${req.user.username || req.user.email}`
    });

  } catch (error) {
    console.error('Error fetching user files:', error);
    res.status(500).json({ message: 'Server error fetching user files', error: error.message });
  }
});

// Multiple Files Delete Route
app.post('/api/delete-multiple', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const { fileIds } = req.body;
    if (!fileIds || !Array.isArray(fileIds) || fileIds.length === 0) {
      return res.status(400).json({ message: 'No file IDs provided for deletion.' });
    }

    if (!req.user || (req.user.userId === undefined && req.user.id === undefined)) {
      console.error("Authentication Error: req.user or user ID (userId/id) is missing in /api/delete-multiple.");
      return res.status(401).json({ message: 'Unauthorized: User information missing from token.' });
    }
    const userId = req.user.userId || req.user.id;
    if (!userId) {
      console.error("CRITICAL ERROR: userId variable is undefined in /api/delete-multiple.");
      return res.status(500).json({ message: 'Server configuration error: User ID could not be determined.' });
    }
    console.log(`DEBUG: User ${userId} requested deletion for file IDs:`, fileIds);

    const encryptedDir = 'encrypted_files';
    let filesDeletedCount = 0;
    let totalBytesFreed = 0;

    const filesToDelete = await File.find({ _id: { $in: fileIds }, userId: userId });

    if (filesToDelete.length === 0) {
      return res.status(404).json({ message: 'No files found for deletion or not owned by user.' });
    }

    for (const fileMetadata of filesToDelete) {
      const encryptedFilePath = path.join(encryptedDir, fileMetadata.encryptedFileName);

      try {
        if (fs.existsSync(encryptedFilePath)) {
          await fsp.unlink(encryptedFilePath);
          console.log(`Deleted file from disk: ${encryptedFilePath}`);
        } else {
          console.warn(`File not found on disk, but found in DB: ${encryptedFilePath}. Skipping disk deletion.`);
        }

        await File.deleteOne({ _id: fileMetadata._id });
        console.log(`Deleted file metadata from DB: ${fileMetadata.originalName} (ID: ${fileMetadata._id})`);
        filesDeletedCount++;
        totalBytesFreed += fileMetadata.fileSize;

        const deleteActivity = new Activity({
          user_id: userId,
          timestamp: new Date(),
          action: 'delete',
          file_name: fileMetadata.originalName,
          description: `Deleted file: ${fileMetadata.originalName}`
        });
        await deleteActivity.save();

      } catch (fileError) {
        console.error(`Error deleting file ${fileMetadata.originalName} (ID: ${fileMetadata._id}):`, fileError);
      }
    }

    if (totalBytesFreed > 0) {
      await User.findByIdAndUpdate(userId, { $inc: { total_storage_used: -totalBytesFreed } });
      console.log(`Updated user ${userId} storage: freed ${totalBytesFreed} bytes.`);
    }

    res.status(200).json({
      message: `Successfully deleted ${filesDeletedCount} file(s).`,
      deletedCount: filesDeletedCount
    });

  } catch (error) {
    console.error('Overall Multiple File Deletion Error:', error);
    res.status(500).json({ message: 'Server error during multiple file deletion.' });
  }
});

// GET /api/profile - Fetch user profile data, storage stats, and recent activities
app.get('/api/profile', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .select('-password -resetPasswordToken -resetPasswordExpire');

    if (!user) return res.status(404).json({ message: 'User not found' });

    const activities = await Activity.find({ user_id: req.user.userId })
      .sort({ timestamp: -1 })
      .limit(10);

    const totalUsedMB = (user.total_storage_used || 0) / (1024 * 1024);
    const storageLimitMB = 1024;

    const storageStats = {
      used: totalUsedMB,
      limit: storageLimitMB
    };

    res.json({
      profile: {
        id: user._id,
        username: user.username,
                email: user.email,
        joinDate: user.createdAt,
                total_storage_used: user.total_storage_used,
                total_storage_limit: user.total_storage_limit
      },
      storageStats: {
        used: user.total_storage_used || 0,
        limit: 1024 // or your logic
      },
      activities: [] // or your logic
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// PUT /api/profile - Update user profile information
app.put('/api/profile', authMiddleware, apiLimiter, [
  check('name', 'Name is required').not().isEmpty(),
  check('email', 'Please include valid email').isEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

  try {
    const { name, email, currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user.userId);

    if (!user) return res.status(404).json({ message: 'User not found' });

    user.name = name;
    user.email = email;

    if (currentPassword && newPassword) {
      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) return res.status(400).json({ message: 'Current password is incorrect' });

      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(newPassword, salt);
    }

    await user.save();

    await new Activity({
      user_id: req.user.userId,
      action: 'profile_update',
      description: 'Updated profile information'
    }).save();

    res.json({ message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Profile update error:', error);
    if (error.code === 11000 && error.keyPattern && error.keyPattern.email) {
      return res.status(400).json({ message: 'Email already in use' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// Redundant endpoint - keeping it but noting it's not used by current frontend
app.get('/api/profile/storage-chart', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const fileTypes = await File.aggregate([
      { $match: { userId: req.user.userId } },
      {
        $group: {
          _id: "$mimeType",
          totalSize: { $sum: "$fileSize" }
        }
      },
      { $sort: { totalSize: -1 } }
    ]);

    const user = await User.findById(req.user.userId);
    const remaining = Math.max(0, 1073741824 - (user.total_storage_used || 0));

    res.json({
      labels: [...fileTypes.map(t => t._id || 'Unknown'), 'Available'],
      datasets: [{
        data: [...fileTypes.map(t => t.totalSize), remaining],
        backgroundColor: [
          '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0',
          '#9966FF', '#FF9F40', '#8AC249', '#EA5545',
          '#F46A9B', '#EF9B20'
        ]
      }]
    });
  } catch (error) {
    console.error('Storage chart error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// NEW: User-Specific File Deletion (single file)
app.delete('/api/delete/:encryptedFileName', authMiddleware, apiLimiter, async (req, res) => {
  const requestedEncryptedFileName = req.params.encryptedFileName;
  const userId = req.user.userId;
  const encryptedDir = 'encrypted_files';

  try {
    const blockchainState = await BlockchainState.findOne({});
    if (!blockchainState || !blockchainState.chain || blockchainState.chain.length === 0) {
      return res.status(404).json({ message: "Blockchain is empty or not found. No files to delete." });
    }

    const currentBlockchain = new Blockchain(blockchainState.chain, blockchainState.difficulty);

    let fileMetadataToDelete = null;

    for (let i = currentBlockchain.chain.length - 1; i >= 0; i--) {
      const block = currentBlockchain.chain[i];
      if (block.data && typeof block.data === 'object' && block.data.encryptedFileName === requestedEncryptedFileName) {
        if (block.data.userId && block.data.userId.toString() === userId.toString()) {
          fileMetadataToDelete = block.data;
          break;
        } else {
          console.warn(`Unauthorized delete attempt: User ${userId} tried to delete file ${requestedEncryptedFileName} belonging to ${block.data.userId}`);
          return res.status(403).json({ message: 'Unauthorized: You can only delete your own files.' });
        }
      }
    }

    if (!fileMetadataToDelete) {
      return res.status(404).json({ message: "File metadata not found on the blockchain for this user." });
    }

    if (fileMetadataToDelete.status === 'deleted') {
      return res.status(400).json({ message: 'File is already marked as deleted on the blockchain.' });
    }

    const encryptedFilePath = path.join(encryptedDir, fileMetadataToDelete.encryptedFileName);
    if (fs.existsSync(encryptedFilePath)) {
      await fsp.unlink(encryptedFilePath);
      console.log(`Encrypted file '${encryptedFilePath}' deleted from disk.`);
    } else {
      console.warn(`Encrypted file '${encryptedFilePath}' not found on disk, but metadata exists on blockchain. Proceeding to update blockchain.`);
    }

    await User.findByIdAndUpdate(req.user.userId, { $inc: { total_storage_used: -(fileMetadataToDelete.fileSize || 0) } });

    const deletionMetadata = {
      ...fileMetadataToDelete,
      status: 'deleted',
      deletionDate: new Date().toISOString(),
      deletedBy: userId,
    };
    const newDeletionBlock = new Block(
      currentBlockchain.chain.length,
      Date.now(),
      deletionMetadata,
      currentBlockchain.getLatestBlock().hasher
    );
    instantDataBackupChain.addBlock(newDeletionBlock); // Use instantDataBackupChain
    console.log("New deletion block added to the blockchain:", newDeletionBlock.hasher);
    console.log("Is chain valid?", instantDataBackupChain.isChainValid()); // Use instantDataBackupChain

    const latestBlockchainState = await BlockchainState.findOne({});
    if (latestBlockchainState) {
      latestBlockchainState.chain = instantDataBackupChain.chain.map(block => ({
        index: block.index,
        timestamp: block.timestamp,
        data: block.data,
        previousHash: block.previousHash,
        hasher: block.hasher,
        nonce: block.nonce
      }));
      latestBlockchainState.difficulty = instantDataBackupChain.difficulty;
      await latestBlockchainState.save();
      console.log("Blockchain state updated in DB with deletion record.");
    } else {
      console.error("Error: Blockchain state document not found during delete update. This should not happen if initialized.");
      return res.status(500).json({ message: "Blockchain state not found in DB." });
    }

    const deleteActivity = new Activity({
      user_id: req.user.userId,
      timestamp: new Date(),
      action: 'delete',
      file_name: fileMetadataToDelete.originalName,
      description: `Deleted file: ${fileMetadataToDelete.originalName}`
    });
    await deleteActivity.save();

    res.status(200).json({
      message: `File '${fileMetadataToDelete.originalName}' (encrypted: ${fileMetadataToDelete.encryptedFileName}) marked as deleted on blockchain and removed from disk.`,
      deletedFileName: fileMetadataToDelete.encryptedFileName,
      blockchainHashOfDeletionRecord: newDeletionBlock.hasher
    });
  } catch (error) {
    console.error('File Delete Error:', error);
    res.status(500).json({ message: 'Server error during file deletion', error: error.message });
  }
});

// Multiple Files Download Route
app.post('/api/download-multiple', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const { fileIds } = req.body;
    if (!fileIds || !Array.isArray(fileIds) || fileIds.length === 0) {
      return res.status(400).json({ message: 'No file IDs provided for download.' });
    }

    if (!req.user || (req.user.userId === undefined && req.user.id === undefined)) {
      console.error("Authentication Error: req.user or user ID (userId/id) is missing in /api/download-multiple.");
      return res.status(401).json({ message: 'Unauthorized: User information missing from token.' });
    }
    const userId = req.user.userId || req.user.id;
    if (!userId) {
      console.error("CRITICAL ERROR: userId variable is undefined in /api/download-multiple.");
      return res.status(500).json({ message: 'Server configuration error: User ID could not be determined.' });
    }
    console.log(`DEBUG: User ${userId} requested download for file IDs:`, fileIds);

    // --- Prepare for Zipping ---
    const archive = archiver('zip', {
      zlib: { level: 9 }
    });

    const archiveName = `InstantBackup_Files_${Date.now()}.zip`;
    res.attachment(archiveName);

    archive.pipe(res);

    const encryptedDir = 'encrypted_files';

    for (const fileId of fileIds) {
      const fileMetadata = await File.findOne({ _id: fileId, userId: userId });

      if (!fileMetadata) {
        console.warn(`File with ID ${fileId} not found or not owned by user ${userId}. Skipping.`);
        continue;
      }

      const encryptedFilePath = path.join(encryptedDir, fileMetadata.encryptedFileName);

      if (!fs.existsSync(encryptedFilePath)) {
        console.error(`Encrypted file not found on disk: ${encryptedFilePath}. Skipping.`);
        continue;
      }

      try {
        const encryptedContentBuffer = await fsp.readFile(encryptedFilePath, 'utf8'); // Read as UTF-8 string for decrypt function
        const decryptedContentBuffer = decrypt(encryptedContentBuffer); // Corrected call

        archive.append(decryptedContentBuffer, { name: fileMetadata.originalName });
        console.log(`Added ${fileMetadata.originalName} to archive.`);

        const downloadActivity = new Activity({
          user_id: userId,
          timestamp: new Date(),
          action: 'download',
          file_name: fileMetadata.originalName,
          file_size: fileMetadata.fileSize,
          description: `Downloaded file: ${fileMetadata.originalName}`
        });
        await downloadActivity.save();

      } catch (fileError) {
        console.error(`Error processing file ${fileMetadata.originalName} (ID: ${fileId}) for download:`, fileError);
      }
    }

    archive.finalize();

    archive.on('end', () => {
      console.log('Archive data has been finalized and output sent.');
    });

    archive.on('error', (err) => {
      console.error('Archiver error:', err);
      res.status(500).json({ message: 'Error creating file archive.' });
    });

  } catch (error) {
    console.error('Overall Multiple File Download Error:', error);
    res.status(500).json({ message: 'Server error during multiple file download.' });
  }
});

// Endpoint to get user's storage usage
app.get('/api/user/storage-usage', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const userId = req.user.userId;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.status(200).json({
      total_storage_used: user.total_storage_used || 0,
      message: `Storage usage for user ${user.username || user.email}`
    });

  } catch (error) {
    console.error('Error fetching storage usage:', error);
    res.status(500).json({ message: 'Server error fetching storage usage.', error: error.message });
  }
});

// Endpoint to get user's activity logs
app.get('/api/user/activities', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const userId = req.user.userId;
    const activities = await Activity.find({ user_id: userId }).sort({ timestamp: -1 });

    res.status(200).json({
      activities: activities,
      totalActivities: activities.length,
      message: `Found ${activities.length} activities for user ${req.user.username || req.user.email}`
    });

  } catch (error) {
    console.error('Error fetching user activities:', error);
    res.status(500).json({ message: 'Server error fetching user activities.', error: error.message });
  }
});

// Admin feedback routes (add these where you have your other routes)
app.get('/api/admin/feedback', authMiddleware, async (req, res) => {
    try {
        // Check if user is admin
        const user = await User.findById(req.user.userId);
        if (!user.isAdmin) {
            return res.status(403).json({ message: 'Not authorized' });
        }

        const feedbacks = await Feedback.find()
            .sort({ createdAt: -1 })
            .populate('user', 'username email');
            
        res.json(feedbacks);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// Route to update feedback status (admin only)
app.put('/api/admin/feedback/:id', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user.isAdmin) {
            return res.status(403).json({ message: 'Not authorized' });
        }

        const { status, adminResponse } = req.body;
        
        const feedback = await Feedback.findByIdAndUpdate(
            req.params.id,
            { status, adminResponse, updatedAt: Date.now() },
            { new: true }
        );
        
        if (!feedback) {
            return res.status(404).json({ message: 'Feedback not found' });
        }
        
        res.json(feedback);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// --- Serve Frontend HTML Files ---
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'login.html')));
app.get('/register.html', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'register.html')));
app.get('/forgot-password.html', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'forgot-password.html')));
app.get('/resetpassword/:token', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'reset-password.html')));
app.get('/dashboard.html', authMiddleware, (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'dashboard.html')));
app.get('/profile.html', authMiddleware, (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'profile.html')));
app.get('/troubleshooter.html', authMiddleware, (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'troubleshooter.html')));
app.get('/home.html', authMiddleware, (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'home.html')));
app.get('/test-profile.html', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'test-profile.html')));
app.get('/profile-fixed.html', authMiddleware, (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'profile-fixed.html')));
app.get('/profile-clean.html', authMiddleware, (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'profile-clean.html')));
app.get('/debug-profile.html', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'debug-profile.html')));

// Catch-all route for the root, redirects to welcome page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'index.html')); // index.html is now the welcome page
});

// Serve static assets from 'frontend' directory for all other paths (must be after specific routes)
app.use(express.static(path.join(__dirname, 'frontend')));
// --- End Serve Frontend HTML Files ---

app.use('/api/profile', profileRoutes);

// --- Server Startup Logic ---
initializeBlockchain().then(() => {
    app.listen(port, () => {
        console.log(`Server listening at http://localhost:${port}`);
    });
}).catch(err => {
    console.error("Failed to start server due to critical initialization error:", err);
    process.exit(1); // Exit if blockchain init fails
});