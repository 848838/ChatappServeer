
const mongoose = require('mongoose');
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const User = require('./Modals/User');
const { Server } = require('socket.io');  // Importing Socket.IO Server
const http = require('http');
const Message = require('./Modals_uiGMS-Server/Message');

const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const port = 5000;

const JWT_SECRET = "hvdvay6ert72839289()aiyg8t87qt72393293883uhefiuh78ttq3ifi78272jdsds039[]]pou89ywe";

// Create HTTP server using the app
const server = http.createServer(app);
const uploadDir = path.join('/tmp', 'uploads');

// Attach Socket.IO to the server
const io = new Server(server, {
    cors: {
        origin: "*",  // Allowing all origins, adjust for security in production
        methods: ["GET", "POST"]
    }
});

// Use middleware
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("Connected to backend server...");
  })
  .catch((err) => {
    console.error("MongoDB error:", err);
  });


// create folder only if not exists
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
        cb(null, `${uniqueSuffix}-${file.originalname}`);
    }
});

const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
        if (!allowedTypes.includes(file.mimetype)) {
            return cb(new Error('Only JPEG, PNG, or GIF files are allowed'), false);
        }
        cb(null, true);
    },
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});


// Login route
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || user.password !== password) {
            return res.status(401).json({ error: 'Email or password incorrect' });
        }

        const token = jwt.sign(
            { id: user._id, email: user.email, name: user.name, profileImage: user.profileImage },
            JWT_SECRET
        );

        res.status(200).json({ token, user: { id: user._id, email: user.email, name: user.name, profileImage: user.profileImage } });
    } catch (error) {
        return res.status(500).json({ error: "Login failed" });
    }
});
app.post('/signup', async (req, res) => {
    try {
        const { name, email, password, profileImage } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ error: 'User already exists' });
        }

        // Create new user
        const newUser = new User({
            name,
            email,
            password, // ⚠️ You should hash this in real apps
            profileImage
        });

        await newUser.save();

        // Create token same as login
        const token = jwt.sign(
            { 
                id: newUser._id, 
                email: newUser.email, 
                name: newUser.name, 
                profileImage: newUser.profileImage 
            },
            JWT_SECRET
        );

        res.status(201).json({
            token,
            user: {
                id: newUser._id,
                email: newUser.email,
                name: newUser.name,
                profileImage: newUser.profileImage
            }
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: "Signup failed" });
    }
});

// User data route
app.post('/userdata', async (req, res) => {
    const { token } = req.body;
    try {
        const decodedUser = jwt.verify(token, JWT_SECRET);
        const user = await User.findOne({ email: decodedUser.email });
        if (!user) return res.status(404).json({ message: "User not found" });
        res.send({ status: "ok", data: user });
    } catch (error) {
        console.error("Error verifying token in /userdata:", error.message);
        return res.status(401).json({ error: "Invalid or expired token" });
    }
});
// const sendPushNotification = (receiverId, message) => {
//     io.to(receiverId).emit('pushNotification', {
//         title: 'New Message',
//         message,
//     });
// };
// Get recent chat users (sorted by last message time)
app.get("/recent-chats", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(400).json({ message: "No token provided" });

    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.id;

    const messages = await Message.find({
      $or: [{ senderId: userId }, { receiverId: userId }],
    }).sort({ timestamp: -1 });

    const userMap = new Map();

    for (let msg of messages) {
      const otherUserId =
        msg.senderId.toString() === userId
          ? msg.receiverId.toString()
          : msg.senderId.toString();

      if (!userMap.has(otherUserId)) {
        const user = await User.findById(otherUserId).select(
          "name profileImage profession hobby"
        );

        if (user) {
          userMap.set(otherUserId, {
            _id: user._id,
            name: user.name,
            profileImage: user.profileImage,
            profession: user.profession,
            hobby: user.hobby,
            lastMessage: msg.message,
            lastMessageTime: msg.timestamp,
          });
        }
      }
    }

    res.json({ status: "ok", users: Array.from(userMap.values()) });
  } catch (e) {
    console.error("recent chats error:", e);
    res.status(500).json({ status: "error", message: e.message });
  }
});

io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    socket.on('userOnline', async (userId) => {
        if (userId) {
            socket.userId = userId; // Store userId in the socket object
            await User.findByIdAndUpdate(socket.userId, { lastOnline: null }); // Set lastOnline to null while they are online
        }
    });

    socket.on('sendMessage', async (messageData) => {
        const { senderId, receiverId, message, imageUri } = messageData;
    
        try {
            // Find sender and receiver from the database
            const sender = await User.findById(senderId).select('name profileImage');
            const receiver = await User.findById(receiverId).select('name profileImage');
    
            if (!sender || !receiver) {
                console.error('Sender or Receiver not found in database');
                return;
            }
    
            // Create new message and save it
            const newMessage = new Message({
                senderId,
                receiverId,
                message,
                imageUri,
                timestamp: new Date(),
            });
    
            await newMessage.save();
    
            // Emit the message to the receiver
            io.to(receiverId).emit('newMessage', {
                _id: newMessage._id,
                senderId,
                senderName: sender.name,
                receiverId,
                message: newMessage.message,
                imageUri: newMessage.imageUri,
                profileImage: sender.profileImage,
                timestamp: newMessage.timestamp,
            });
    
            // Optionally emit confirmation to sender
            io.to(senderId).emit('messageSentConfirmation', { status: 'Message sent successfully' });
    
            console.log('Message saved and sent:', newMessage);
        } catch (error) {
            console.error('Error handling sendMessage event:', error);
        }
    });
    
    

    
    socket.on('disconnect', async () => {
        console.log('User disconnected:', socket.id);

        if (socket.userId) {
            // Set lastOnline when the user is truly offline
            await User.findByIdAndUpdate(socket.userId, { lastOnline: new Date() });
            console.log(`Updated last online for user ${socket.userId}`);
        }
    });
});

app.get('/user/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('name profileImage lastOnline');
        if (!user) return res.status(404).json({ error: 'User not found' });

        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/messages/images', async (req, res) => {
    try {
        const { userId } = req.query;
        const messages = await Message.find({
            $or: [{ senderId: userId }, { receiverId: userId }],
            imageUri: { $ne: null }
        }).sort({ timestamp: -1 });

        res.json({ status: 'ok', images: messages });
    } catch (error) {
        res.status(500).json({ status: 'error', message: error.message });
    }
});


// Route to send a message with an image
// Route to send a message with an image
app.post('/sendMessageWithImage', upload.single('image'), async (req, res) => {
    const { senderId, receiverId, message } = req.body;

    // Check if sender, receiver, and at least one of message or image is provided
    if (!senderId || !receiverId || (!message && !req.file)) {
        return res.status(400).json({ message: 'Sender, receiver, and either a message or an image are required' });
    }

    try {
        let imageUri = null;
        if (req.file) {
            imageUri = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
        }

        const sender = await User.findById(senderId).select('name profileImage');
        if (!sender) {
            return res.status(404).json({ message: 'Sender not found' });
        }

        const newMessage = new Message({
            senderId,
            receiverId,
            message: message || '', // Use an empty string if no text message
            imageUri,
            timestamp: new Date(),
        });

        await newMessage.save();

        io.emit('message', {
            message: newMessage.message,
            senderName: sender.name,
            senderId,
            receiverId,
            profileImage: sender.profileImage,
            timestamp: newMessage.timestamp,
            imageUri,
        });

        res.status(200).json({ status: 'ok', message: newMessage });
    } catch (error) {
        console.error('Error sending message with image:', error);
        res.status(500).json({ status: 'error', message: 'Failed to send message with image', error: error.message });
    }
});
app.post('/Stories', upload.single('stories'), async (req, res) => {
    const { userId } = req.body;

    if (!userId) {
        return res.status(400).json({ message: 'User ID is required' });
    }

    if (!req.file) {
        return res.status(400).json({ message: 'Story image is required' });
    }

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const storiesUri = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;

        // Ensure stories is an array before pushing
        if (!Array.isArray(user.stories)) {
            user.stories = [];
        }

        user.stories.push(storiesUri); // Append the new story
        await user.save();

        io.emit('stories', { userId, stories: user.stories });

        res.status(200).json({ status: 'ok', stories: user.stories });
    } catch (error) {
        console.error('Error saving stories:', error);
        res.status(500).json({ status: 'error', message: 'Failed to save stories', error: error.message });
    }
});

app.get('/stories', async (req, res) => {
    try {
        const users = await User.find().select('stories name profileImage');
        
        // Ensure we send stories for all users, not just the logged-in user
        const allStories = users.map(user => ({
            userId: user._id,
            stories: user.stories.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)), // Sort by timestamp (most recent first)
            profileImage: user.profileImage,
            name: user.name,
        })).sort((a, b) => b.stories[0]?.timestamp - a.stories[0]?.timestamp); // Sort users by the most recent story

        res.status(200).json({
            status: 'ok',
            stories: allStories,
        });
    } catch (error) {
        console.error('Error fetching stories:', error);
        res.status(500).json({ status: 'error', message: 'Failed to fetch stories', error: error.message });
    }
});


// Fetch messages between users
app.get('/messages', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1]; // Bearer token
    const { receiverId } = req.query;

    if (!token) {
        return res.status(400).json({ message: 'No token provided' });
    }

    if (!receiverId) {
        return res.status(400).json({ message: 'Receiver ID is required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const senderId = decoded.id;

        // Fetch all messages between the logged-in user and the receiver
        const messages = await Message.find({
            $or: [
                { senderId, receiverId },
                { senderId: receiverId, receiverId: senderId },
            ],
        }).sort({ timestamp: 1 }); // Sort by timestamp in ascending order (oldest first)

        // Populate sender information for each message
        const messagesWithProfile = await Promise.all(
            messages.map(async (msg) => {
                const sender = await User.findById(msg.senderId).select('name profileImage');
                return {
                    ...msg._doc,
                    senderName: sender?.name || 'Unknown',
                    profileImage: sender?.profileImage || 'default.jpg',
                    imageUri: msg.imageUri , // Ensure imageUri is included
                };
            })
        );

        if (!messagesWithProfile || messagesWithProfile.length === 0) {
            return res.status(404).json({ message: 'No messages found' });
        }

        res.status(200).json({ messages: messagesWithProfile });
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ message: 'Error fetching messages', error: error.message });
    }
});
// On backend (Express) for handling message deletion
app.delete('/messages/:id', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1]; // Bearer token

        if (!token) {
            return res.status(400).json({ message: 'No token provided' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const userId = decoded.id;

        // Find the message by ID
        const message = await Message.findById(req.params.id);

        if (!message) {
            return res.status(404).json({ status: 'error', message: 'Message not found' });
        }

        // Ensure the message belongs to the current user (either sender or receiver)
        if (message.senderId.toString() !== userId && message.receiverId.toString() !== userId) {
            return res.status(403).json({ status: 'error', message: 'You cannot delete this message' });
        }
io.emit('messageDeleted', req.params.id); // Broadcasting the deleted message ID
        // Delete the message
        await message.deleteOne();
        res.status(200).json({ status: 'ok', message: 'Message deleted' });
    } catch (err) {
        console.error('Error deleting message:', err);
        res.status(500).json({ status: 'error', message: 'Failed to delete message' });
    }
});
// update can be made by login user and reflected to other useers too

app.put('/updateprofile', upload.single('profileImage'), async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1]; // Bearer token

    if (!token) {
        return res.status(400).json({ message: 'No token provided' });
    }

    try {
        const decodedToken = jwt.verify(token, JWT_SECRET);
        const userId = decodedToken.id;

        const updateData = { name: req.body.name, profession: req.body.profession };

        // Handle profile image
        if (req.file) {
            updateData.profileImage = `https://chatapp-serveer.vercel.app/uploads/${req.file.filename}`;
        }

        // Update the user in the database
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            updateData,
            { new: true, runValidators: true } // Return updated document and validate input
        );

        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found' });
        }
        io.emit('profileUpdated', updatedUser); // Broadcasting the updated user

        res.status(200).json({ status: 'ok', user: updatedUser });
    } catch (error) {
        console.error('Error updating profile:', error.message);
        res.status(500).json({ message: 'Error updating profile', error: error.message });
    }
});


//fetch other users in server
app.get('/users', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1]; // Assuming Bearer token
    if (!token) {
        return res.status(400).json({ message: 'No token provided' });
    }

    try {
        // Decode the JWT token
        const decoded = jwt.verify(token, JWT_SECRET);
        const loggedInUserId = decoded.id; // Assuming the JWT contains the user ID in 'id' field

        if (!loggedInUserId) {
            return res.status(400).json({ message: 'User not authenticated' });
        }

        // Fetch all users excluding the logged-in user
        const users = await User.find({ _id: { $ne: loggedInUserId } })
            .select('-password -verificationToken') // Exclude sensitive fields like password and verificationToken
            .exec();

        if (!users || users.length === 0) {
            return res.status(404).json({ message: 'No users found' });
        }

        res.status(200).json({ users });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ message: 'Error fetching users', error: error.message });
    }
});
// Start the server
server.listen(port, () => {
    console.log(`App listening on port ${port}`);
});
