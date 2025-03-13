const mongoose = require('mongoose');
const express = require('express');
const bodyParser = require('body-parser');


const jwt = require("jsonwebtoken");
const cors = require("cors");

const User = require('./Modals/User');
const { Server } = require('socket.io');  // Importing Socket.IO Server
const Task = require('./Modals/Task');



const app = express();
const port = 5000;

const JWT_SECRET = "hvdvay6ert72839289()aiyg8t87qt72393293883uhefiuh78ttq3ifi78272jdsds039[]]pou89ywe";



// Attach Socket.IO to the server


// Use middleware
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log("connected to backend server...");
}).catch((err) => {
    console.log('error found', err);
});



app.post('/signup', async (req, res) => {
    try {
        const { name, email, password, profileImage } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        // Create a new user without hashing the password
        const newUser = new User({
            name,
            email,
            password,  // Storing password as plain text (not recommended)
            profileImage: profileImage || '', // Default empty string if no image
        });

        await newUser.save();

        // Generate JWT token
        const token = jwt.sign(
            { id: newUser._id, email: newUser.email, name: newUser.name, profileImage: newUser.profileImage },
            JWT_SECRET
        );

        res.status(201).json({ message: "User registered successfully", token, user: newUser });
    } catch (error) {
        res.status(500).json({ message: "Signup failed", error: error.message });
    }
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


// Fetch messages between users

// On backend (Express) for handling message deletion

// update can be made by login user and reflected to other useers too

app.post('/taskadding', async (req, res) => {
    const { token, taskName, description } = req.body;

    try {
        if (!token) return res.status(401).json({ message: "Unauthorized" });

        const decodedUser = jwt.verify(token, JWT_SECRET);
        const userId = decodedUser.id;

        const newTask = new Task({ userId, taskName, description });
        await newTask.save();

        res.status(201).json({ message: "Task added successfully", task: newTask });
    } catch (error) {
        res.status(500).json({ message: "Error adding tasks", error: error.message });
    }
});

app.get('/tasks', async (req, res) => {
    const { token } = req.headers;

    try {
        if (!token) return res.status(401).json({ message: "Unauthorized" });

        const decodedUser = jwt.verify(token, JWT_SECRET);
        const userId = decodedUser.id;

        const tasks = await Task.find({ userId }).sort({ createdAt: -1 }).exec();

        res.status(200).json({ tasks });
    } catch (error) {
        res.status(500).json({ message: "Error fetching tasks", error: error.message });
    }
});
app.put('/task/:taskId', async (req, res) => {
    const { token, taskName, description } = req.body;
    const { taskId } = req.params;

    try {
        if (!token) return res.status(401).json({ message: "Unauthorized" });

        const decodedUser = jwt.verify(token, JWT_SECRET);
        const userId = decodedUser.id;

        const task = await Task.findOne({ _id: taskId, userId });

        if (!task) return res.status(404).json({ message: "Task not found" });

        task.taskName = taskName || task.taskName;
        task.description = description || task.description;
        await task.save();

        res.status(200).json({ message: "Task updated successfully", task });
    } catch (error) {
        res.status(500).json({ message: "Error updating task", error: error.message });
    }
});
app.delete('/task/:taskId', async (req, res) => {
    const { token } = req.headers;
    const { taskId } = req.params;

    try {
        if (!token) return res.status(401).json({ message: "Unauthorized" });

        const decodedUser = jwt.verify(token, JWT_SECRET);
        const userId = decodedUser.id;

        const task = await Task.findOneAndDelete({ _id: taskId, userId });

        if (!task) return res.status(404).json({ message: "Task not found" });

        res.status(200).json({ message: "Task deleted successfully" });
    } catch (error) {
        res.status(500).json({ message: "Error deleting task", error: error.message });
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
app.listen(port, () => {
    console.log(`App listening on port ${port}`);
});
