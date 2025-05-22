require('dotenv').config(); // Load environment variables

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000; // Use port from environment or default to 3000

// Database connection pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// Middleware to parse JSON request bodies
app.use(express.json());

// Middleware to protect routes
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Get token from "Bearer TOKEN"

    if (token == null) {
        return res.sendStatus(401); // If no token, unauthorized
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403); // If token is invalid, forbidden
        }
        req.user = user; // Attach user information to the request
        next(); // Proceed to the next middleware or route handler
    });
};


// --- API Routes ---

// Registration Route
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    // Basic validation
    if (!username || !email || !password) {
        return res.status(400).json({ message: 'Usuario, correo y conraseña son datos requeridos para el registro' });
    }

    if (password.length < 8) {
        return res.status(400).json({ message: 'La contraseña debe tener al menos 8 caracteres' });
    }

    try {
        // Check if email already exists
        const emailCheck = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (emailCheck.rows.length > 0) {
            return res.status(400).json({ message: 'Email ya se encuentra registrado' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds

        // Insert the new user into the database
        const newUser = await pool.query(
            'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email',
            [username, email, hashedPassword]
        );

        res.status(201).json({ message: 'Usuario registrado exitosamente', user: newUser.rows[0] });

    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Ha ocurrido un error el registro' });
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Usuario y contraseña son datos obligatorios' });
    }

    try {
        // Find the user by username
        const userResult = await pool.query('SELECT Id, UserName, password, Email, Rol, SuperUser FROM users WHERE username = $1', [username]);

        if (userResult.rows.length === 0) {
            return res.status(401).json({ message: 'Usuario no se encuentra registrado.' });
        }

        const user = userResult.rows[0];

        // Compare the provided password with the stored hashed password
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Contraseña incorecta.' });
        }

        // Generate a JWT for session management
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '1h' } // Token expires in 1 hour
        );

        res.status(200).json({ message: 'Sessión iniciada exitosamente.',
                                token,
                             user: {
                                id: user.id,
                                username: user.username,
                                email: user.email,
                                rol: user.rol,
                                superuser: user.superuser}});

    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Ha ocurrido un error al iniciar sesión' });
    }
});

// Logout Route (Protected)
app.post('/logout', authenticateToken, (req, res) => {
    // For JWTs, server-side logout is often just a confirmation.
    // The client is responsible for discarding the token.
    res.status(200).json({ message: 'Sessión cerrada exitosamente.' });
});


// Start the server
app.listen(port, () => {
    console.log(`Server running on port3 ${port}`);
});
