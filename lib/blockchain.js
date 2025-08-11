// lib/blockchain.js

import crypto from 'crypto';

class Block {
  // Added 'nonce' and 'hash' to constructor for proper re-instantiation from DB
  constructor(index, timestamp, data, previousHash = '', nonce = 0, hash = '') {
    this.index = index;
    this.timestamp = timestamp;
    this.data = data;
    this.previousHash = previousHash;
    this.nonce = nonce; // Crucial: ensure nonce is preserved when loading from DB
    this.hasher = hash || this.calculateHash(); // If hash is provided (from DB), use it, else calculate
  }

  // Method to calculate the SHA256 hash of the block's content
  calculateHash() {
    return crypto.createHash('sha256').update(
      this.index +
      this.previousHash +
      this.timestamp +
      JSON.stringify(this.data) +
      this.nonce // Include nonce in hash calculation for PoW
    ).digest('hex');
  }

  // Simplified Proof-of-Work method
  mineBlock(difficulty) {
    while (this.hasher.substring(0, difficulty) !== Array(difficulty + 1).join("0")) {
      this.nonce++;
      this.hasher = this.calculateHash();
    }
    console.log("Block mined: " + this.hasher);
  }
}

// --- Blockchain Class (Modified for DB Persistence) ---
class Blockchain {
  // Modified constructor to accept optional existing chain data and difficulty from DB
  constructor(existingChainData = [], difficulty = 2) {
    this.difficulty = difficulty;

    if (existingChainData.length === 0) {
      // If no existing chain data, create a new chain with a genesis block
      this.chain = [this.createGenesisBlock()];
      console.log("No existing blockchain found. Created new Genesis Block.");
    } else {
      // If existing chain data is provided (from DB), re-instantiate Block objects
      this.chain = existingChainData.map(blockData => {
        // Pass all necessary data to Block constructor, including the stored hash and nonce
        const block = new Block(
          blockData.index,
          blockData.timestamp,
          blockData.data,
          blockData.previousHash,
          blockData.nonce,
          blockData.hasher // Pass the stored hash for initial assignment
        );
        // Important: Recalculate hash to verify the loaded data, even if 'hasher' was passed.
        // This ensures the hash is correct given the loaded data and nonce, detecting any tampering.
        if (block.hasher !== block.calculateHash()) {
          console.warn(`Block ${block.index} loaded from DB has a hash mismatch! Recalculating (should not happen if valid).`);
          block.hasher = block.calculateHash(); // Re-calculate to ensure consistency
        }
        return block;
      });
      console.log(`Blockchain loaded with ${this.chain.length} blocks from DB.`);
    }
  }

  // The first block in the chain
  createGenesisBlock() {
    return new Block(0, Date.now(), "Genesis Block", "0");
  }

  // Get the latest block in the chain
  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  // Method to add a new block to the chain
  addBlock(newBlock) {
    // Link the new block to the previous one
    newBlock.previousHash = this.getLatestBlock().hasher;
    // Mine the new block to satisfy Proof-of-Work
    newBlock.mineBlock(this.difficulty);
    // Add the mined block to the chain
    this.chain.push(newBlock);
  }

  // Method to validate the entire chain's integrity
  isChainValid() {
    for (let i = 1; i < this.chain.length; i++) {
      const currentBlock = this.chain[i];
      const previousBlock = this.chain[i - 1];

      // Check if the current block's hash is correctly calculated based on its contents
      if (currentBlock.hasher !== currentBlock.calculateHash()) {
        console.log('Chain invalid: Current block hash mismatch!');
        return false;
      }

      // Check if the current block correctly points to the previous block's hash
      if (currentBlock.previousHash !== previousBlock.hasher) {
        console.log('Chain invalid: Previous hash mismatch!');
        return false;
      }
    }
    return true; // If all checks pass, the chain is valid
  }
}

// Export both Block and Blockchain so they can be imported in server.js
export { Block, Blockchain };