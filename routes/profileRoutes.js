import express from 'express';
import auth from '../middleware/auth.js';
import User from '../models/User.js';
import { check, validationResult } from 'express-validator';
import bcrypt from 'bcrypt';
import Feedback from '../models/Feedback.js';

const router = express.Router();

// Get user profile
router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        // TODO: Replace with actual data usage calculation
        const dataUsage = {
            totalUsed: 1024, // in MB
            limit: 5120,    // in MB
            lastUpdated: new Date()
        };
        res.json({ user, dataUsage });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// Update user profile (name)
router.put(
    '/',
    auth,
    [check('name', 'Name is required').not().isEmpty()],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        try {
            const { name } = req.body;
            const user = await User.findByIdAndUpdate(
                req.user.id,
                { name },
                { new: true }
            ).select('-password');
            res.json(user);
        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server Error');
        }
    }
);

// Update password
router.put(
    '/password',
    auth,
    [
        check('currentPassword', 'Current password is required').exists(),
        check('newPassword', 'New password must be at least 6 characters').isLength({ min: 6 })
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        try {
            const user = await User.findById(req.user.id);
            const isMatch = await bcrypt.compare(req.body.currentPassword, user.password);
            if (!isMatch) {
                return res.status(400).json({ errors: [{ msg: 'Current password is incorrect' }] });
            }
            const salt = await bcrypt.genSalt(10);
            user.password = await bcrypt.hash(req.body.newPassword, salt);
            await user.save();
            res.json({ msg: 'Password updated successfully' });
        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server Error');
        }
    }
);

// Add this route to profileRoutes.js
router.get('/feedback', auth, async (req, res) => {
    try {
        const feedbacks = await Feedback.find({ user: req.user.id })
            .sort({ createdAt: -1 });
        res.json(feedbacks);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// Update the existing feedback submission route
router.post(
    '/feedback',
    auth,
    [
        check('subject', 'Subject is required').not().isEmpty(),
        check('description', 'Description is required').not().isEmpty()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const user = await User.findById(req.user.id);
            if (!user) {
                return res.status(404).json({ msg: 'User not found' });
            }

            const { subject, description } = req.body;
            const newFeedback = new Feedback({
                user: req.user.id,
                username: user.username,
                email: user.email,
                subject,
                description,
                status: 'open'
            });

            await newFeedback.save();
            
            // Log activity
            await new Activity({
                user_id: req.user.id,
                action: 'feedback_submitted',
                description: `Submitted feedback: "${subject}"`
            }).save();

            res.json({ msg: 'Feedback submitted successfully', feedback: newFeedback });
        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server Error');
        }
    }
);

export default router;