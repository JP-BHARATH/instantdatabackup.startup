import mongoose from 'mongoose';

const activitySchema = new mongoose.Schema({
    user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now
    },
    action: {
        type: String,
        enum: [
            'login',
            'logout',
            'upload',
            'download',
            'delete',
            'profile_update',
            'password_change',
            'feedback_submitted', // Added this
            'account_created'
        ],
        required: true
    },
    description: {
        type: String,
        required: true
    },
    file_name: String,
    file_size: Number
});

const Activity = mongoose.model('Activity', activitySchema);
export default Activity;