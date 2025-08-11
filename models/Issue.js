import mongoose from 'mongoose';

const IssueSchema = new mongoose.Schema({
    user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    username: { // Or email, depending on what you want to store/display
        type: String,
        required: true
    },
    serial_number: {
        type: String,
        required: true
    },
    subject: {
        type: String,
        required: true,
        trim: true,
        maxlength: 100
    },
    description: {
        type: String,
        required: true,
        trim: true
    },
    status: {
        type: String,
        enum: ['new', 'in_progress', 'resolved', 'closed'],
        default: 'new'
    },
    reported_at: {
        type: Date,
        default: Date.now
    },
    resolved_at: Date,
    resolution_notes: String
});

const Issue = mongoose.model('Issue', IssueSchema);
export default Issue;