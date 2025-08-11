// models/File.js
import mongoose from 'mongoose';

const fileSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId, // Link to your User model
        ref: 'User', // IMPORTANT: This must match the name of your User Mongoose model
        required: true,
    },
    originalName: {
        type: String,
        required: true,
    },
    encryptedFileName: { // The unique name given to the encrypted file on disk
        type: String,
        required: true,
        unique: true, // Ensures no two files have the same disk name in the DB
    },
    // encryptedFilePath: { // Optional: You might not need this if you always store in `encrypted_files`
    //     type: String,
    //     required: false,
    // },
    fileSize: {
        type: Number, // Size in bytes
        required: true,
    },
    mimeType: {
        type: String,
        required: false, // Useful for previewing files
    },
    encryptedFileHash: { // Hash of the encrypted content for integrity checks
        type: String,
        required: true,
    },
    uploadDate: {
        type: Date,
        default: Date.now,
    },
}, {
    timestamps: true // Automatically adds createdAt and updatedAt fields
});

const File = mongoose.model('File', fileSchema);

export default File;