const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt'); // Import bcrypt library
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session'); // Import express-session
const jwt = require('jsonwebtoken');
const uuid = require('uuid');


const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(session({
    secret: 'your-secret-key', // Change this to a secure random key
    resave: false,
    saveUninitialized: false
}));

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/simple-form-data', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
    console.log('Connected to MongoDB');
});

// Define a schema for your form data
const formDataSchema = new mongoose.Schema({
    firstname: String,
    lastname: String,
    gender: String,
    email: String,
    password: String, // Store hashed password
    qualification: String,
    profession: String,
});

const FormDataModel = mongoose.model('FormData', formDataSchema);

// Configure Passport.js LocalStrategy with bcrypt
passport.use(new LocalStrategy(
    {
        usernameField: 'email',
        passwordField: 'password'
    },
    async (email, password, done) => {
        try {
            const user = await FormDataModel.findOne({ email });

            if (!user) {
                return done(null, false, { message: 'User not found' });
            }

            const passwordMatch = await bcrypt.compare(password, user.password);

            if (!passwordMatch) {
                return done(null, false, { message: 'Incorrect password' });
            }

            return done(null, user);
        } catch (error) {
            return done(error);
        }
    }
));

// Serialize and deserialize user
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await FormDataModel.findById(id);
        done(null, user);
    } catch (error) {
        done(error);
    }
});

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Serve the React app at the home route

// Handle data from the form's "Finish" button
app.post('/api/submit', async (req, res) => {
    const formData = req.body;

    try {
        // Hash the password before saving it to the MongoDB database
        const hashedPassword = await bcrypt.hash(formData.password, 10); // 10 rounds of salting
        formData.password = hashedPassword;

        // Save the form data to the MongoDB database
        const newFormData = new FormDataModel(formData);
        await newFormData.save();
        console.log(res);
        console.log('Data saved to MongoDB:', newFormData);
        res.json({ message: 'Data saved successfully' });
    } catch (error) {
        console.error('Error saving data to MongoDB:', error);
        res.status(500).send('Error saving data to the database');
    }
});

// Route for user login using Passport.js
app.post('/api/login', passport.authenticate('local', { failureRedirect: '/' }), (req, res) => {
    const user = req.user;
    // Generate JWT access token (expires in 10 minutes)
    const accessToken = jwt.sign({ userId: user._id }, "secret", { expiresIn: '24h' });

    res.json({ message: 'Login successful', accessToken });
});

// Middleware to verify JWT access token
const verifyAccessToken = (req, res, next) => {
    const accessToken = req.headers.authorization?.split(' ')[1];

    if (!accessToken) {
        return res.status(401).json({ message: 'Access token not provided' });
    }

    try {
        const decoded = jwt.verify(accessToken, "secret");
        req.userId = decoded.userId;
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid access token' });
    }
};


// Protected route example
app.get('/api/profile', verifyAccessToken, async (req, res) => {
    try {
        const user = await FormDataModel.findById(req.userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Send the user data back to the client
        res.json(user);
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});






// Start the server
const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
