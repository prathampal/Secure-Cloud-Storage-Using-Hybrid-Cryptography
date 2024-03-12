const express = require('express');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const path = require('path');
const mongoose = require('mongoose'); // Import Mongoose
const passwordValidator = require('password-validator'); // Install 'password-validator' package
const app = express();
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto'); // Import crypto module

// AES encryption function
function encryptFile(fileBuffer, encryptionKey) {
    //  encryptionKey is a Buffer
   // console.log('Encrypting File - Input:', fileBuffer, 'Key:', encryptionKey)
    if (!Buffer.isBuffer(encryptionKey)) {
        throw new Error('Invalid encryption key format.');
    }
    //  the key length is 32 bytes
    if (encryptionKey.length !== 32) {
        throw new Error('Invalid encryption key length.');
    }
    const iv = crypto.randomBytes(16); // Generating a unique IV for each encryption
    const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
    let encrypted = cipher.update(fileBuffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
}
// Decrypt file function
function decryptFile(encryptedFile, encryptionKey) {
    try {
        console.log('Encrypted File:', encryptedFile);
        console.log('Decrypting File - Input:', encryptedFile, 'Key:', encryptionKey);

        if (!encryptedFile || typeof encryptedFile !== 'object' || !('iv' in encryptedFile) || !('encryptedData' in encryptedFile)) {
            throw new Error('Invalid encrypted file format: Missing properties.');
        }
        const iv = Buffer.from(encryptedFile.iv, 'hex');
        // Convert encryptionKey to Buffer if it's in string format
        if (typeof encryptionKey === 'string') {
            encryptionKey = Buffer.from(encryptionKey, 'hex');
        }
        const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, iv);
        let decrypted = decipher.update(Buffer.from(encryptedFile.encryptedData, 'hex'));
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        console.log('Decrypted File (Buffer):', decrypted);
        console.log('Decrypted File (String):', decrypted.toString('hex')); // Convert Buffer to hexadecimal string
        return decrypted;
    } catch (error) {
        console.error('Error decrypting file:', error.message);
        return null; // or throw an error depending on your error handling strategy
    }
}


// express-session
app.use(session({
    secret: 'secret_key_124', // secret phrase
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        maxAge: 60 * 60 * 1000 // Session timeout in milliseconds (e.g., 1 hour)
    }
}));
app.use((req, res, next) => {
    const userDirectory = `public/uploads/${req.session.userId}/`;
    fs.mkdirSync(userDirectory, { recursive: true }); // Create directory if it doesn't exist
    next();
});

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const userDirectory = `public/uploads/${req.session.userId}/`;
        fs.mkdirSync(userDirectory, { recursive: true }); // Create directory if it doesn't exist
        cb(null, userDirectory);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/secure_cloud_storage', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

//  a Mongoose schema for users
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    encryptionKey: { type: String, required: true }, 
});


// Schema for password policies
const schema = new passwordValidator();
schema
    .is().min(8) // Minimum length
    .is().max(100) // Maximum length
    .has().uppercase() // Must have uppercase letters
    .has().lowercase() // Must have lowercase letters
    .has().digits() // Must have digits
    .has().not().spaces(); // Should not have spaces
const User = mongoose.model('User', userSchema);

// Registration endpoint
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        // Validate input
        if (!username || !email || !password) {
            return res.status(400).send('Please provide username, email, and password.');
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).send('Please provide a valid email address.');
        }

        // Check if user already exists
        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return res.status(409).send('Email is already registered.');
        }

        const existingUsername = await User.findOne({ username });
        if (existingUsername) {
            return res.status(409).send('Username is already taken.');
        }

        // Validate password against the defined schema
        if (!schema.validate(password)) {
            return res.status(400).send('Password does not meet complexity requirements.');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate an initial encryption key
        const encryptionKey = crypto.randomBytes(32).toString('hex'); // Convert to hexadecimal string

        // Create a new user in the database with encryptionKey
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            encryptionKey,
        });

        await newUser.save();

        res.status(201).send('User registered successfully.');
    } catch (error) {
        // Log the entire error object
        console.error('Error registering user:', error);

        // Or log the error message
        console.error('Error registering user:', error.message);

        // Sending a more detailed error response
        res.status(500).send(`Error registering user: ${error.message}`);
    }
});

// login endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Retrieve the user from the database based on username
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(401).json({ error: 'invalid_username' });
        }

        // Compare the entered password with the hashed password in the database
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ error: 'incorrect_password' });
        }

        // Set session ID for logged-in user
        req.session.userId = user._id;
        req.session.encryptionKey = user.encryptionKey; // Store as a hexadecimal string
        console.log('Session after login:', req.session);
        // For successful login, respond with a success message or user data
        res.status(200).json({ message: 'Login successful', user });
    } catch (error) {
        // Handle server errors
        console.error(error);
        res.status(500).json({ error: 'server_error' });
    }
});

//  middleware to check if the user is logged in
const isAuthenticated = async (req, res, next) => {
    try {
        if (req.session.userId) {
            // Fetch user from the database based on the user ID stored in the session
            const user = await User.findById(req.session.userId);

            if (user) {
                // Attach user and encryption key to the request object
                req.user = {
                    _id: user._id,
                    encryptionKey: Buffer.from(req.session.encryptionKey, 'hex'),
                };

                // Proceed to the next middleware/route handler
                next();
            } else {
                console.error('User not found in the database');
                res.status(401).send('Unauthorized access.');
            }
        } else {
            // User is not logged in, redirect to login page or send an error response
            console.error('Unauthorized access. Session:', req.session);
            res.status(401).send('Unauthorized access.');
        }
    } catch (error) {
        console.error('Error checking authentication:', error);
        res.status(500).send('Internal server error');
    }
    //console.log('Session ID in isAuthenticated:', req.session.userId);
   // console.log('Encryption Key in isAuthenticated:', req.session.encryptionKey);

};

// Usage of isAuthenticated middleware
app.get('/secured-route', isAuthenticated, (req, res) => {
    // Route accessible only to authenticated users
    // Handle secured route logic here
    res.send('Access granted to secured route.');
});
// home route handler
app.get('/home', isAuthenticated, (req, res) => {
    // Render the home/dashboard page or send relevant data
    res.send('Welcome to the dashboard!'); 
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Error logging out.');
        }
        res.clearCookie('connect.sid'); // Clear session cookie
        res.status(200).send('Logged out successfully.');
    });
});

// Endpoint to handle file uploads
const upload = multer({ storage });
// File upload endpoint
app.post('/upload-encrypted', isAuthenticated, upload.array('myFiles[]'), async (req, res) => {
    try {
        const userEncryptionKey = Buffer.from(req.session.encryptionKey, 'hex'); // Convert hex string to Buffer
        const files = req.files;
        if (!userEncryptionKey) {
            return res.status(400).send('Encryption key not found for the user.');
        }
        // Process each uploaded file
        for (const file of files) {
            const fileBuffer = fs.readFileSync(file.path); // Read file as a buffer

            try {
                const encryptedFile = encryptFile(fileBuffer, userEncryptionKey);
                // Store the encrypted file in the uploads directory
                fs.writeFileSync(`public/uploads/${req.session.userId}/${file.filename}`, JSON.stringify(encryptedFile), 'utf8');
            } catch (encryptError) {
                console.error('Error encrypting file:', encryptError);
                return res.status(500).send('Failed to encrypt files');
            }
        }
        res.status(200).send('Files uploaded and encrypted successfully');
    } catch (error) {
        console.error('Error uploading files:', error);
        res.status(500).send('Failed to upload files');
    }
});

// Endpoint to download files
app.get('/download/:filename', isAuthenticated, async (req, res) => {
    const userDirectory = `public/uploads/${req.session.userId}/`;
    const fileName = req.params.filename;
    const file = path.join(userDirectory, fileName);

    try {
        console.log('Request to download file. User ID:', req.session.userId);
        if (fs.existsSync(file)) {
            const user = await User.findById(req.session.userId);
            if (user) {
                console.log('User found. User:', user);
                if (req.session.encryptionKey && req.session.encryptionKey.length === 64) { // Check length of hexadecimal string
                    const userEncryptionKey = Buffer.from(req.session.encryptionKey, 'hex'); // Convert hex string to Buffer
                    console.log('User Encryption Key from Session:', userEncryptionKey);
                    const fileBuffer = fs.readFileSync(file, 'utf8');
                    console.log('File Buffer Length:', fileBuffer.length);
                    if (fileBuffer.length > 0) {
                        const decryptedFile = decryptFile(JSON.parse(fileBuffer), userEncryptionKey);
                        console.log('Decrypted File (Buffer):', decryptedFile);
                        if (decryptedFile) {
                            console.log('Decrypted File Length:', decryptedFile.length);
                            res.set('Content-Disposition', `attachment; filename=${fileName}`);
                            res.send(decryptedFile);
                        } else {
                            console.error('Failed to decrypt file:', decryptedFile);
                            res.status(500).send('Failed to decrypt file');
                        }
                    } else {
                        console.error('File Buffer length is 0');
                        res.status(500).send('File Buffer length is 0');
                    }
                } else {
                    console.error('Invalid encryption key in session:', req.session.encryptionKey);
                    res.status(400).send('Invalid encryption key in session.');
                }
            } else {
                console.error('User not found:', req.session.userId);
                res.status(404).send('User not found.');
            }
        } else {
            console.error('File not found:', file);
            res.status(404).send('File not found');
        }
    } catch (error) {
        console.error('Error downloading file:', error);
        res.status(500).send('Failed to download file');
    }
});
// Endpoint to delete files
app.delete('/delete/:filename', isAuthenticated, (req, res) => {
    const userDirectory = `public/uploads/${req.session.userId}/`; // Adjust path for user-specific files
    const fileName = req.params.filename;
    const file = path.join(userDirectory, fileName);

    fs.unlink(file, (err) => {
        if (err) {
            console.error('Error deleting file:', err);
            res.status(500).send('Failed to delete file');
        } else {
            res.status(200).send('File deleted successfully');
        }
    });
});

// Endpoint to list uploaded files
app.get('/list-files', isAuthenticated, (req, res) => {
    const userDirectory = `public/uploads/${req.session.userId}/`;
    fs.readdir(userDirectory, (err, files) => {
        if (err) {
            console.error('Error reading directory:', err);
            res.status(500).send('Failed to list files');
        } else {
            res.json({ files });
        }
    });
});

const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
