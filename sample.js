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
// import auth from './middleware/auth.js'; // NOTE: Commented out. We will use the custom authMiddleware defined below for consistency with new features.
import multer from 'multer';
import path from 'path';
import fsp from 'fs/promises'; // For promise-based file system operations
import fs from 'fs';          // For synchronous file system operations (e.g., existsSync)
import crypto from 'crypto';  // For cryptographic operations like generating tokens
import { Block, Blockchain } from './lib/blockchain.js'; // Ensure this is only imported once at the top
import BlockchainState from './models/BlockchainState.js'; // Import your BlockchainState model
import cors from 'cors';
import helmet from 'helmet';
import { check, validationResult } from 'express-validator';
import rateLimit from 'express-rate-limit';
import mime from 'mime-types'; // <--- ADDED THIS IMPORT for MIME type detection
import { v4 as uuidv4 } from 'uuid'; // For unique serial numbers
import Activity from './models/Activity.js'; // Adjust path as needed, add .js extension
import Issue from './models/Issue.js';     // Adjust path as needed, add .js extension
import sendEmail from './utils/emailSender.js'; // <--- ADDED THIS IMPORT

const app = express();
const port = 3000;

// --- Encryption Configuration ---
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
                    previousHash: block.previousHash,
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
app.use(express.json());

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
// It's recommended to move this to `./middleware/auth.js` for better organization.
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ message: 'No token provided' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token format is "Bearer <token>"' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Failed to authenticate token' });
        // Ensure your JWT payload from login route includes userId, username, serialNumber
        req.user = decoded;
        next();
    });
};
// --- End Custom Authentication Middleware ---


// Serve static files from the 'frontend' directory
app.use(express.static(path.join(__dirname, 'frontend')));

// --- API Routes ---

// --- Consolidated User Registration Endpoint (/api/register) ---
// This route now includes username, serial_number, total_storage_used, last_login logic.
app.post(
    '/api/register',
    authLimiter, // Apply rate limiting to registration attempts
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
            console.log('Register - received email:', email); // Debug log
            console.log('Register - received username:', username); // Debug log

            let user = await User.findOne({ email });
            if (user) {
                return res.status(400).json({ message: 'User already exists' });
            }

            const serialNumber = uuidv4(); // Generate a unique serial number

            // Password hashing is handled by the pre-save hook in your User model
            user = new User({
                username,
                email,
                password: password, // The pre-save hook will hash this
                serial_number: serialNumber,
                total_storage_used: 0,
                last_login: new Date()
            });

            await user.save(); // This will trigger the pre('save') hook in User.js to hash the password
            console.log('Register - User saved successfully to DB.');

            const payload = {
                user: {
                    id: user.id, // MongoDB _id
                    userId: user._id, // Alias for consistency with some frontend usage if needed
                    username: user.username,
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
// This route now includes last_login update and activity logging.
app.post(
    '/api/login',
    authLimiter, // Apply rate limiting to login attempts
    [
        check('email', 'Please include a valid email').isEmail(),
        check('password', 'Password is required').exists(),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: errors.array()[0].msg });
        }

        const { email, password } = req.body;

        try {
            console.log('Login - received email:', email);

            let user = await User.findOne({ email });
            if (!user) {
                console.log('Login - User not found for email:', email);
                return res.status(400).json({ message: 'Invalid credentials' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            console.log('Login - bcrypt.compare result (true/false):', isMatch);
            if (!isMatch) {
                return res.status(400).json({ message: 'Invalid credentials' });
            }

            // Update last_login on successful login
            user.last_login = new Date();
            await user.save(); // This also triggers the pre-save hook if you have one, but it should be fine.

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
                    id: user.id, // MongoDB _id
                    userId: user._id, // Alias for consistency
                    username: user.username,
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
                    res.json({ message: 'Logged in successfully', token, username: user.username });
                }
            );
        } catch (err) {
            console.error('Login Error:', err.message);
            res.status(500).send('Server error during login');
        }
    }
);

// --- NEW: Forgot Password Request Endpoint ---
app.post(
    '/api/forgotpassword',
    apiLimiter, // Rate limit this endpoint to prevent abuse
    [
        check('email', 'Please include a valid email').isEmail(),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: errors.array()[0].msg });
        }

        const { email } = req.body;

        try {
            const user = await User.findOne({ email });
            if (!user) {
                // Return a generic success message to avoid email enumeration
                return res.status(200).json({ message: 'If a user with that email exists, a password reset link has been sent.' });
            }

            // Generate a reset token and hash it for storage
            const rawResetToken = crypto.randomBytes(32).toString('hex'); // The token to send in email
            const hashedResetToken = await bcrypt.hash(rawResetToken, 10); // Hash for database storage

            user.resetPasswordToken = hashedResetToken; // Store the HASHED token
            user.resetPasswordExpire = Date.now() + 3600000; // Token valid for 1 hour
            await user.save();

            // Create the reset URL (IMPORTANT: Use your frontend URL here!)
            const resetUrl = `https://3000-firebase-instant-data-backup-1748249505922.cluster-nzwlpk54dvagsxetkvxzbvslyi.cloudworkstations.dev/resetpassword/${rawResetToken}`; // Send the RAW token

            const emailContent = `
                <p>You are receiving this because you (or someone else) have requested the reset of the password for your account.</p>
                <p>Please click on the following link, or paste this into your browser to complete the process within one hour of receiving it:</p>
                <p><a href="${resetUrl}">${resetUrl}</a></p>
                <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
            `;

            const emailResult = await sendEmail(user.email, 'Password Reset Request', emailContent);

            if (emailResult.success) {
                res.status(200).json({ message: 'Password reset link sent successfully.' });
            } else {
                console.error('Error sending reset email:', emailResult.error);
                res.status(500).json({ message: 'Error sending password reset email.' });
            }

        } catch (err) {
            console.error('Forgot Password Error:', err.message);
            res.status(500).send('Server error during password reset request.');
        }
    }
);

// --- NEW: Reset Password Endpoint ---
app.post(
    '/api/resetpassword/:token',
    apiLimiter, // Rate limit this endpoint
    [
        check('password', 'Password must be 6 or more characters').isLength({ min: 6 }),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: errors.array()[0].msg });
        }

        const { token } = req.params; // The raw token from the URL
        const { password } = req.body; // The new password

        try {
            // Find users with a valid (non-expired) reset token
            const users = await User.find({
                resetPasswordExpire: { $gt: Date.now() } // Token must not be expired
            });

            let user = null;
            // Iterate through valid tokens and compare hashed values
            for (const u of users) {
                if (u.resetPasswordToken && await bcrypt.compare(token, u.resetPasswordToken)) {
                    user = u;
                    break;
                }
            }

            if (!user) {
                return res.status(400).json({ message: 'Invalid or expired password reset token.' });
            }

            // Update user's password (pre-save hook will handle hashing)
            user.password = password; // Assign plaintext new password

            // Clear reset token fields
            user.resetPasswordToken = undefined;
            user.resetPasswordExpire = undefined;

            await user.save(); // This will trigger the pre('save') hook to hash the new password

            res.status(200).json({ message: 'Password has been reset successfully.' });

        } catch (err) {
            console.error('Reset Password Error:', err.message);
            res.status(500).send('Server error during password reset.');
        }
    }
);


// --- API for User Feedback/Bug Report ---
app.post('/api/report-issue', authMiddleware, async (req, res) => {
    const { subject, description } = req.body;
    const userId = req.user.userId;
    const username = req.user.username;
    const serialNumber = req.user.serialNumber;

    if (!subject || !description) {
        return res.status(400).json({ message: 'Subject and description are required.' });
    }

    try {
        const newIssue = new Issue({
            user_id: userId,
            username: username,
            serial_number: serialNumber,
            subject: subject,
            description: description,
            status: 'new',
            reported_at: new Date()
        });

        await newIssue.save();
        res.status(201).json({ message: 'Issue reported successfully!' });
    } catch (error) {
        console.error('Error reporting issue:', error);
        res.status(500).json({ message: 'Failed to report issue.' });
    }
});

// File Upload, Encryption, Local Storage, and Blockchain Integration
app.post('/api/upload', authMiddleware, apiLimiter, upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
    }

    const originalFilePath = req.file.path;
    const originalFileName = req.file.originalname;
    const encryptedDir = 'encrypted_files';

    try {
        const fileBuffer = await fsp.readFile(originalFilePath);
        const encryptedContentHex = encrypt(fileBuffer);

        await fsp.mkdir(encryptedDir, { recursive: true });

        const encryptedFileNameOnDisk = `${crypto.randomBytes(16).toString('hex')}.enc`;
        const encryptedFilePath = path.join(encryptedDir, encryptedFileNameOnDisk);
        await fsp.writeFile(encryptedFilePath, encryptedContentHex);

        const encryptedFileHash = crypto.createHash('sha256').update(encryptedContentHex).digest('hex');

        await fsp.unlink(originalFilePath); // Delete the temporary file

        const fileMetadata = {
            originalName: originalFileName,
            mimeType: req.file.mimetype,
            encryptedFileName: encryptedFileNameOnDisk,
            encryptedFilePath: encryptedFilePath,
            fileSize: req.file.size,
            encryptedFileHash: encryptedFileHash,
            uploadDate: new Date().toISOString(),
            userId: req.user.userId
        };
        const newBlock = new Block(
            instantDataBackupChain.chain.length,
            Date.now(),
            fileMetadata,
            instantDataBackupChain.getLatestBlock().hasher
        );
        instantDataBackupChain.addBlock(newBlock);
        console.log("New block added to the blockchain:", newBlock.hasher);
        console.log("Is chain valid?", instantDataBackupChain.isChainValid());

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

        // Update user's storage usage
        await User.findByIdAndUpdate(req.user.userId, { $inc: { total_storage_used: req.file.size } });

        // Log activity
        const uploadActivity = new Activity({
            user_id: req.user.userId,
            timestamp: new Date(),
            action: 'upload',
            file_name: req.file.originalname,
            file_size: req.file.size,
            description: `Uploaded file: ${req.file.originalname}`
        });
        await uploadActivity.save();

        res.status(200).json({
            message: 'File uploaded, encrypted, stored locally, and metadata added to blockchain!',
            originalName: originalFileName,
            mimeType: req.file.mimetype,
            encryptedFileName: encryptedFileNameOnDisk,
            encryptedFilePath: encryptedFilePath,
            fileSize: req.file.size,
            blockchainHash: newBlock.hasher
        });

    } catch (error) {
        console.error('File Upload/Encryption/Blockchain Error:', error);
        if (originalFilePath && fs.existsSync(originalFilePath)) {
            await fsp.unlink(originalFilePath).catch(e => console.error("Failed to delete temp file during error:", e));
        }
        res.status(500).json({ message: 'Server error during file upload and encryption' });
    }
});

// Endpoint to view the entire Blockchain (can be public or protected, for now public for easy inspection)
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
            return res.status(404).json({ message: "Blockchain is empty or not found. No files to restore." });
        }

        const currentBlockchain = new Blockchain(blockchainState.chain, blockchainState.difficulty);

        let fileMetadata = null;
        // Iterate from the end of the chain to get the latest metadata for a given file
        for (let i = currentBlockchain.chain.length - 1; i >= 0; i--) {
            const block = currentBlockchain.chain[i];
            if (block.data && typeof block.data === 'object' && block.data.encryptedFileName === requestedEncryptedFileName) {
                fileMetadata = block.data;
                break; // Found the latest relevant block for this file
            }
        }

        if (!fileMetadata) {
            return res.status(404).json({ message: "File metadata not found on the blockchain." });
        }

        // IMPORTANT: Authorization check
        if (fileMetadata.userId && fileMetadata.userId.toString() !== req.user.userId.toString()) { // Compare ObjectIds correctly
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
        res.setHeader('Content-Disposition', `inline; filename="${fileMetadata.originalName}"`); // 'inline' for preview, 'attachment' for download
        res.setHeader('Content-Length', decryptedBuffer.length);
        res.status(200).send(decryptedBuffer);

        console.log(`File '${fileMetadata.originalName}' restored successfully.`);

        // Log activity
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

        // Iterate from the END of the blockchain to ensure the latest status for each file
        for (let i = currentBlockchain.chain.length - 1; i >= 0; i--) {
            const block = currentBlockchain.chain[i];
            if (block.data && typeof block.data === 'object' && block.data.userId && block.data.userId.toString() === userId.toString()) {
                const encryptedFileName = block.data.encryptedFileName;
                if (encryptedFileName && !fileStatuses.has(encryptedFileName)) {
                    // Store the block data and whether it's marked as deleted
                    fileStatuses.set(encryptedFileName, { blockData: block.data, isDeleted: block.data.status === 'deleted' });
                }
            }
        }

        const userFiles = [];
        // Convert Map entries to an array and filter out deleted ones
        // Sort by uploadDate (oldest first for consistent display, or newest first if preferred)
        const activeFiles = Array.from(fileStatuses.values())
                                .filter(({ isDeleted }) => !isDeleted)
                                .map(({ blockData }) => ({
                                    originalName: blockData.originalName,
                                    encryptedFileName: blockData.encryptedFileName,
                                    fileSize: blockData.fileSize,
                                    uploadDate: blockData.uploadDate,
                                    blockchainHash: blockData.hasher, // Include blockchain hash of the block that recorded this file's state
                                    mimeType: blockData.mimeType
                                }));

        // Sort by uploadDate, descending (newest first)
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


// NEW: User-Specific File Deletion
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

        // Iterate from the END of the chain to find the most recent block for this file
        for (let i = currentBlockchain.chain.length - 1; i >= 0; i--) {
            const block = currentBlockchain.chain[i];
            if (block.data && typeof block.data === 'object' && block.data.encryptedFileName === requestedEncryptedFileName) {
                // IMPORTANT: Ensure the file belongs to the authenticated user
                if (block.data.userId && block.data.userId.toString() === userId.toString()) {
                    fileMetadataToDelete = block.data;
                    break; // Found the latest relevant block for the current user
                } else {
                    // If a file with this encryptedFileName exists but belongs to another user,
                    // we should still return unauthorized to avoid leaking info.
                    console.warn(`Unauthorized delete attempt: User ${userId} tried to delete file ${requestedEncryptedFileName} belonging to ${block.data.userId}`);
                    return res.status(403).json({ message: 'Unauthorized: You can only delete your own files.' });
                }
            }
        }

        if (!fileMetadataToDelete) {
            return res.status(404).json({ message: "File metadata not found on the blockchain for this user." });
        }

        // Check if the file is already marked as deleted
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

        // Deduct storage usage
        await User.findByIdAndUpdate(req.user.userId, { $inc: { total_storage_used: -(fileMetadataToDelete.fileSize || 0) } });


        // Create a new block to record the logical deletion on the blockchain
        const deletionMetadata = {
            ...fileMetadataToDelete, // Copy existing metadata
            status: 'deleted',       // Mark as deleted
            deletionDate: new Date().toISOString(),
            deletedBy: userId,
        };
        const newDeletionBlock = new Block(
            currentBlockchain.chain.length,
            Date.now(),
            deletionMetadata,
            currentBlockchain.getLatestBlock().hasher
        );
        currentBlockchain.addBlock(newDeletionBlock);
        console.log("New deletion block added to the blockchain:", newDeletionBlock.hasher);
        console.log("Is chain valid?", currentBlockchain.isChainValid());

        const latestBlockchainState = await BlockchainState.findOne({});
        if (latestBlockchainState) {
            latestBlockchainState.chain = currentBlockchain.chain.map(block => ({
                index: block.index,
                timestamp: block.timestamp,
                data: block.data,
                previousHash: block.previousHash,
                hasher: block.hasher,
                nonce: block.nonce
            }));
            latestBlockchainState.difficulty = currentBlockchain.difficulty;
            await latestBlockchainState.save();
            console.log("Blockchain state updated in DB with deletion record.");
        } else {
            console.error("Error: Blockchain state document not found during delete update. This should not happen if initialized.");
            return res.status(500).json({ message: "Blockchain state not found in DB." });
        }

        // Log activity
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
        // Find activities for the user, sorted by timestamp descending
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


// --- Serve Frontend HTML Files ---
// Serve specific HTML files directly (order matters for specific paths)
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'login.html')));
app.get('/register.html', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'register.html')));
app.get('/forgot-password.html', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'forgot-password.html')));
app.get('/resetpassword/:token', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'reset-password.html')));
app.get('/dashboard.html', (req, res) => res.sendFile(path.join(__dirname, 'frontend', 'dashboard.html')));

// Catch-all route for the root, redirects to welcome page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'index.html')); // index.html is now the welcome page
});

// Serve static assets from 'frontend' directory for all other paths (must be after specific routes)
app.use(express.static(path.join(__dirname, 'frontend')));
// --- End Serve Frontend HTML Files ---


// --- Server Startup Logic ---
initializeBlockchain().then(() => {
    app.listen(port, () => {
        console.log(`Server listening at http://localhost:${port}`);
    });
}).catch(err => {
    console.error("Failed to start server due to critical initialization error:", err);
    process.exit(1); // Exit if blockchain init fails
});