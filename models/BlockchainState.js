// models/BlockchainState.js

import mongoose from 'mongoose';

const BlockSchema = new mongoose.Schema({
  index: { type: Number, required: true },
  timestamp: { type: Number, required: true }, // Store as Unix timestamp
  data: { type: Object, required: true },     // JSON data of the block
  previousHash: { type: String, required: true },
  hasher: { type: String, required: true },   // Current block's hash
  nonce: { type: Number, required: true }
});

const BlockchainStateSchema = new mongoose.Schema({
  // We'll store the entire chain as an array of Block documents
  chain: [BlockSchema],
  difficulty: { type: Number, default: 2 }, // Store the mining difficulty
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Add a pre-save hook to update the updatedAt field
BlockchainStateSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const BlockchainState = mongoose.model('BlockchainState', BlockchainStateSchema);

export default BlockchainState;