// import { fileURLToPath } from 'url';
// import { dirname } from 'path';

// const __filename = fileURLToPath(import.meta.url);
// const __dirname = dirname(__filename);

// import express from 'express';
// import bodyParser from 'body-parser';
// import path from 'path';
// import jwt from 'jsonwebtoken';  // For authentication tokens
// import bcrypt from 'bcryptjs';  // For password hashing

// // --- Database Setup (Example: MongoDB with Mongoose) ---
// import mongoose from 'mongoose';
// import User from '../models/User.js';     // Assuming your User model is in ../models/User.js - ADD .js
// import Activity from '../models/Activity.js'; // Assuming an Activity model - ADD .js
// import Issue from '../models/Issue.js';     // Assuming an Issue model - ADD .js
// // Connect to MongoDB
// mongoose.connect('mongodb://localhost:27017/your_database_name', {
   
// })
// .then(() => console.log('MongoDB connected for admin panel...'))
// .catch(err => console.error('MongoDB connection error:', err));

// // --- Admin User Model (for admin panel authentication) ---
// const adminSchema = new mongoose.Schema({
//     username: { type: String, required: true, unique: true },
//     password: { type: String, required: true }
// });

// adminSchema.pre('save', async function(next) {
//     if (this.isModified('password')) {
//         this.password = await bcrypt.hash(this.password, 10);
//     }
//     next();
// });

// const Admin = mongoose.model('Admin', adminSchema);

// // --- JWT Secret (KEEP THIS SECURE AND IN ENVIRONMENT VARIABLES) ---
// const JWT_SECRET = process.env.JWT_SECRET || 'supersecretadminkey'; // Use a strong, random key in production!

// const adminApp = express();
// adminApp.use(bodyParser.json());
// adminApp.use(bodyParser.urlencoded({ extended: true }));

// // Serve static files for the admin frontend
// adminApp.use(express.static(path.join(__dirname, 'public')));

// // Middleware to protect admin routes
// const authenticateAdmin = (req, res, next) => {
//     const authHeader = req.headers['authorization'];
//     if (!authHeader) return res.status(401).json({ message: 'No token provided' });

//     const token = authHeader.split(' ')[1]; // Assuming "Bearer TOKEN"
//     if (!token) return res.status(401).json({ message: 'Token format is "Bearer <token>"' });

//     jwt.verify(token, JWT_SECRET, (err, decoded) => {
//         if (err) return res.status(403).json({ message: 'Failed to authenticate token' });
//         req.adminUser = decoded; // Contains admin username from token
//         next();
//     });
// };

// // --- Admin Login Endpoint ---
// adminApp.post('/admin/login', async (req, res) => {
//     const { username, password } = req.body;

//     // Basic validation
//     if (!username || !password) {
//         return res.status(400).json({ message: 'Username and password are required' });
//     }

//     try {
//         const adminUser = await Admin.findOne({ username });
//         if (!adminUser) {
//             return res.status(401).json({ message: 'Invalid username or password' });
//         }

//         const isMatch = await bcrypt.compare(password, adminUser.password);
//         if (!isMatch) {
//             return res.status(401).json({ message: 'Invalid username or password' });
//         }

//         // Generate JWT token for admin
//         const token = jwt.sign({ username: adminUser.username }, JWT_SECRET, { expiresIn: '1h' });
//         res.status(200).json({ message: 'Login successful', token });

//     } catch (error) {
//         console.error('Admin login error:', error);
//         res.status(500).json({ message: 'Internal server error' });
//     }
// });

// // --- Admin API Endpoints (Protected by authenticateAdmin middleware) ---

// // API to get all users
// adminApp.get('/admin/api/users', authenticateAdmin, async (req, res) => {
//     try {
//         // Fetch all users, excluding sensitive data like password
//         const users = await User.find({}, { username: 1, email: 1, serial_number: 1, total_storage_used: 1, last_login: 1 });
//         res.status(200).json(users);
//     } catch (error) {
//         console.error('Error fetching users:', error);
//         res.status(500).json({ message: 'Failed to fetch users' });
//     }
// });

// // API to get activity log for a specific user (or all activities)
// adminApp.get('/admin/api/activities', authenticateAdmin, async (req, res) => {
//     const { serialNumber } = req.query; // Admin can query by serial number
//     let query = {};
//     if (serialNumber) {
//         const user = await User.findOne({ serial_number: serialNumber });
//         if (user) {
//             query.user_id = user._id; // Filter by user ID
//         } else {
//             return res.status(404).json({ message: 'User not found for the given serial number' });
//         }
//     }

//     try {
//         const activities = await Activity.find(query)
//             .sort({ timestamp: -1 }) // Sort by most recent
//             .limit(100); // Limit number of activities for performance
//         res.status(200).json(activities);
//     } catch (error) {
//         console.error('Error fetching activities:', error);
//         res.status(500).json({ message: 'Failed to fetch activities' });
//     }
// });

// // API to get all reported issues
// adminApp.get('/admin/api/issues', authenticateAdmin, async (req, res) => {
//     try {
//         const issues = await Issue.find({}).sort({ reported_at: -1 });
//         res.status(200).json(issues);
//     } catch (error) {
//         console.error('Error fetching issues:', error);
//         res.status(500).json({ message: 'Failed to fetch issues' });
//     }
// });

// // API to update an issue's status or add admin notes
// adminApp.put('/admin/api/issues/:id', authenticateAdmin, async (req, res) => {
//     const { id } = req.params;
//     const { status, admin_notes } = req.body;

//     if (!status && !admin_notes) {
//         return res.status(400).json({ message: 'No update data provided.' });
//     }

//     try {
//         const update = {};
//         if (status) update.status = status;
//         if (admin_notes) update.admin_notes = admin_notes;

//         const updatedIssue = await Issue.findByIdAndUpdate(id, update, { new: true });

//         if (!updatedIssue) {
//             return res.status(404).json({ message: 'Issue not found' });
//         }
//         res.status(200).json({ message: 'Issue updated successfully', issue: updatedIssue });
//     } catch (error) {
//         console.error('Error updating issue:', error);
//         res.status(500).json({ message: 'Failed to update issue' });
//     }
// });

// // Create a default admin user if one doesn't exist (for testing)
// async function createDefaultAdmin() {
//     try {
//         const adminExists = await Admin.findOne({ username: 'admin' });
//         if (!adminExists) {
//             const defaultAdmin = new Admin({ username: 'admin', password: 'adminpassword' }); // Change this in production!
//             await defaultAdmin.save();
//             console.log('Default admin user created: admin / adminpassword');
//         }
//     } catch (error) {
//         console.error('Error creating default admin:', error);
//     }
// }
// // createDefaultAdmin(); // Uncomment this line to create a default admin on server start

// const ADMIN_PORT = 3001; // Admin panel runs on a different port
// adminApp.listen(ADMIN_PORT, () => {
//     console.log(`Arca Admin Panel backend listening on port ${ADMIN_PORT}`);
// });