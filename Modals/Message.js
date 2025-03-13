const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    senderId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    receiverId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    message: {
        type: String,

    },
    imageUri: { type: String, required: false }, // Optional field for image or file URL


    timestamp: {
        type: Date,
        default: Date.now
    }
});

const Message = mongoose.model('Message', messageSchema);
module.exports = Message;
