import mongoose from 'mongoose'; // Or const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect('mongodb+srv://jpbharath413:rPBuuQU29hjntBYg@cluster0.bvrzc0n.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'); // Replace with your MongoDB URI
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1); // Exit process with failure
  }
};

export default connectDB; // Or module.exports = connectDB;