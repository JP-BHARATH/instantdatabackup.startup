import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        // required: true, // You might want this or derive from email
        unique: true, // If usernames should be unique
        sparse: true // Allows for null values if username is optional
    },
    email: {
        type: String,
        required: true,
        unique: true,
        match: [/.+@.+\..+/, 'Please enter a valid email address']
    },
    password: {
        type: String,
        required: true
    },
    serial_number: { // New field
        type: String,
        unique: true,
        required: true,
        default: () => uuidv4() // Set default using uuidv4
    },
    total_storage_used: { // New field
        type: Number,
        default: 0
    },
    last_login: { // New field
        type: Date,
        default: Date.now
    },
    resetPasswordToken: String, // New field for password reset
    resetPasswordExpire: Date // New field for password reset
});

// Hash the password before saving (if it's new or modified)
UserSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
    }
    next();
});

const User = mongoose.model('User', UserSchema);
export default User;