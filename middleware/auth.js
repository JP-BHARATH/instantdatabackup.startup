// middleware/auth.js

import jwt from 'jsonwebtoken';

const auth = (req, res, next) => {
    // Get token from header
    const token = req.header('x-auth-token'); // Conventionally, tokens are sent in 'x-auth-token' header

    // Check if not token
    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }

    try {
        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Attach user from token payload to the request object
        req.user = decoded.user; // decoded.user will contain { id: user._id }
        next(); // Move to the next middleware or route handler
    } catch (err) {
        console.error('Auth middleware error:', err);
        res.status(401).json({ message: 'Token is not valid' });
    }
};

export default auth; // Export the middleware